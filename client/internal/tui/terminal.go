//go:build darwin || linux

package tui

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
	"latch.local/client/internal/app"
)

type Input = app.Command
type Terminal struct {
	file                *os.File
	out                 io.Writer
	saved               *term.State
	ctx                 context.Context
	cancel              context.CancelFunc
	wakeRead, wakeWrite *os.File
	updates             chan app.Snapshot
	inputs              chan Input
	raw                 chan []byte
	done, readerDone    chan struct{}
	once                sync.Once
	color               bool
	inputErr            error
}

// New owns raw-mode restoration, but the caller owns closing the terminal file.
// Readiness waits on both input and a cancellation pipe without periodic polling.
func New(file *os.File, out io.Writer, color bool) (*Terminal, error) {
	if !term.IsTerminal(int(file.Fd())) {
		return nil, errors.New("interactive terminal required")
	}
	saved, err := term.MakeRaw(int(file.Fd()))
	if err != nil {
		return nil, errors.New("could not enter terminal mode")
	}
	r, w, err := os.Pipe()
	if err != nil {
		_ = term.Restore(int(file.Fd()), saved)
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	t := &Terminal{file: file, out: out, saved: saved, ctx: ctx, cancel: cancel, wakeRead: r, wakeWrite: w, updates: make(chan app.Snapshot, 1), inputs: make(chan Input, 16), raw: make(chan []byte, 16), done: make(chan struct{}), readerDone: make(chan struct{}), color: color}
	if _, err = io.WriteString(out, "\x1b[?1049h\x1b[2J\x1b[H\x1b[?2004h"); err != nil {
		cancel()
		r.Close()
		w.Close()
		_ = term.Restore(int(file.Fd()), saved)
		return nil, errors.New("terminal output failed")
	}
	go t.read()
	go t.loop()
	return t, nil
}
func (t *Terminal) Events() <-chan Input { return t.inputs }
func (t *Terminal) Render(s app.Snapshot) {
	select {
	case <-t.ctx.Done():
		return
	default:
	}
	select {
	case t.updates <- s:
		return
	default:
	}
	select {
	case <-t.updates:
	default:
	}
	select {
	case t.updates <- s:
	case <-t.ctx.Done():
	}
}
func (t *Terminal) Close() error {
	var restore error
	t.once.Do(func() {
		t.cancel()
		_, _ = t.wakeWrite.Write([]byte{1})
		<-t.readerDone
		<-t.done
		_, _ = io.WriteString(t.out, "\x1b[0m\x1b[?2004l\x1b[?25h\x1b[?1049l")
		restore = term.Restore(int(t.file.Fd()), t.saved)
		_ = t.wakeRead.Close()
		_ = t.wakeWrite.Close()
	})
	return restore
}
func (t *Terminal) emit(input Input) bool {
	select {
	case t.inputs <- input:
		return true
	case <-t.ctx.Done():
		return false
	}
}
func (t *Terminal) read() {
	defer close(t.readerDone)
	defer close(t.raw)
	var buf [256]byte
	for {
		cancelled, err := waitReadable(int(t.file.Fd()), int(t.wakeRead.Fd()))
		if err != nil {
			t.inputErr = errors.New("terminal readiness failed")
			return
		}
		if cancelled {
			return
		}
		n, err := unix.Read(int(t.file.Fd()), buf[:])
		if err == unix.EINTR || err == unix.EAGAIN {
			continue
		}
		if err != nil || n == 0 {
			t.inputErr = errors.New("terminal input closed")
			return
		}
		data := append([]byte(nil), buf[:n]...)
		select {
		case t.raw <- data:
		case <-t.ctx.Done():
			clear(data)
			return
		}
	}
}
func (t *Terminal) loop() {
	defer close(t.done)
	defer close(t.inputs)
	resize := make(chan os.Signal, 1)
	signal.Notify(resize, syscall.SIGWINCH)
	defer signal.Stop(resize)
	var snapshot app.Snapshot
	var editor Editor
	var decoder Decoder
	var previous []string
	scroll := 0
	focus := false
	escape := time.NewTimer(time.Hour)
	if !escape.Stop() {
		<-escape.C
	}
	defer escape.Stop()
	var escapeC <-chan time.Time
	draw := func() {
		width, height, err := term.GetSize(int(t.file.Fd()))
		if err != nil {
			width, height = 80, 24
		}
		screen := Layout(snapshot, editor, width, height, scroll, focus)
		if len(previous) != len(screen.Rows) {
			previous = nil
		}
		_, err = io.WriteString(t.out, Diff(previous, screen, t.color))
		if err != nil {
			t.cancel()
		}
		previous = screen.Rows
	}
	apply := func(keys []Key) bool {
		for _, key := range keys {
			switch key.Kind {
			case "submit":
				text := editor.Text
				editor.Clear()
				if text != "" && !t.emit(Input{Text: text}) {
					return false
				}
				scroll = 0
			case "quit":
				_ = t.emit(Input{Quit: true})
				return false
			case "cancel":
				editor.Clear()
				if !t.emit(Input{Cancel: true}) {
					return false
				}
			case "tab":
				focus = !focus
			case "pageup":
				scroll = min(10000, scroll+10)
			case "pagedown":
				scroll = max(0, scroll-10)
			default:
				editor.Apply(key)
			}
		}
		return true
	}
	defer func() { editor.Clear(); clear(snapshot.Lines); clear(previous); clear(decoder.pending) }()
	for {
		select {
		case <-t.ctx.Done():
			return
		case s := <-t.updates:
			if s.ClearID != snapshot.ClearID {
				scroll = 0
				clear(snapshot.Lines)
				clear(previous)
				previous = nil
			}
			if s.Secret != snapshot.Secret || s.Prompt != snapshot.Prompt {
				editor.Clear()
			}
			snapshot = s
			draw()
		case <-resize:
			previous = nil
			draw()
		case <-escapeC:
			escapeC = nil
			if !apply(decoder.Escape()) {
				return
			}
			draw()
		case data, ok := <-t.raw:
			if !ok {
				_ = t.emit(Input{Quit: true, Err: t.inputErr})
				return
			}
			keys := decoder.Feed(data)
			clear(data)
			if !apply(keys) {
				return
			}
			if !escape.Stop() {
				select {
				case <-escape.C:
				default:
				}
			}
			escapeC = nil
			if len(decoder.pending) == 1 && decoder.pending[0] == 27 {
				escape.Reset(40 * time.Millisecond)
				escapeC = escape.C
			}
			draw()
		}
	}
}
