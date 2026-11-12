package tui

import (
	"strings"
	"unicode/utf8"

	"github.com/rivo/uniseg"
)

type Key struct{ Kind, Text string }

// Decoder handles arbitrarily split UTF-8 and escape sequences with bounded
// pending storage. Bracketed paste cannot submit a line or invoke navigation.
type Decoder struct {
	pending []byte
	paste   bool
}

func (d *Decoder) Feed(data []byte) []Key {
	d.pending = append(d.pending, data...)
	var out []Key
	for len(d.pending) > 0 {
		if d.pending[0] == 27 {
			if len(d.pending) == 1 {
				break
			}
			if d.pending[1] != '[' {
				d.pending = d.pending[1:]
				if !d.paste {
					out = append(out, Key{Kind: "cancel"})
				}
				continue
			}
			end := -1
			for i := 2; i < len(d.pending); i++ {
				if d.pending[i] >= 0x40 && d.pending[i] <= 0x7e {
					end = i
					break
				}
			}
			if end < 0 {
				if len(d.pending) > 32 {
					d.pending = nil
				}
				break
			}
			seq := string(d.pending[:end+1])
			d.pending = d.pending[end+1:]
			if seq == "\x1b[200~" {
				d.paste = true
				continue
			}
			if seq == "\x1b[201~" {
				d.paste = false
				continue
			}
			if d.paste {
				continue
			}
			names := map[string]string{"\x1b[D": "left", "\x1b[C": "right", "\x1b[H": "home", "\x1b[F": "end", "\x1b[1~": "home", "\x1b[4~": "end", "\x1b[3~": "delete", "\x1b[5~": "pageup", "\x1b[6~": "pagedown", "\x1b[A": "up", "\x1b[B": "down"}
			if kind := names[seq]; kind != "" {
				out = append(out, Key{Kind: kind})
			}
			continue
		}
		if !utf8.FullRune(d.pending) {
			break
		}
		r, n := utf8.DecodeRune(d.pending)
		d.pending = d.pending[n:]
		if r == utf8.RuneError && n == 1 {
			continue
		}
		if d.paste {
			if r == '\n' || r == '\r' || r == '\t' {
				r = ' '
			}
			if r >= 32 && r != 127 {
				out = append(out, Key{Kind: "text", Text: Sanitize(string(r))})
			}
			continue
		}
		kind := ""
		switch r {
		case '\r', '\n':
			kind = "submit"
		case 3, 4:
			kind = "quit"
		case 8, 127:
			kind = "backspace"
		case 1:
			kind = "home"
		case 5:
			kind = "end"
		case 21:
			kind = "clear"
		case 11:
			kind = "kill"
		case '\t':
			kind = "tab"
		}
		if kind != "" {
			out = append(out, Key{Kind: kind})
		} else if r >= 32 {
			safe := Sanitize(string(r))
			if safe != "" {
				out = append(out, Key{Kind: "text", Text: safe})
			}
		}
	}
	return out
}
func (d *Decoder) Escape() []Key {
	if len(d.pending) == 1 && d.pending[0] == 27 {
		d.pending = nil
		if !d.paste {
			return []Key{{Kind: "cancel"}}
		}
	}
	return nil
}

type Editor struct {
	Text   string
	Cursor int
}

func (e *Editor) Clear() { e.Text = ""; e.Cursor = 0 }
func (e *Editor) left() int {
	last := 0
	g := uniseg.NewGraphemes(e.Text[:e.Cursor])
	for g.Next() {
		start, _ := g.Positions()
		last = start
	}
	return last
}
func (e *Editor) right() int {
	g := uniseg.NewGraphemes(e.Text[e.Cursor:])
	if g.Next() {
		_, end := g.Positions()
		return e.Cursor + end
	}
	return e.Cursor
}
func (e *Editor) Apply(key Key) {
	switch key.Kind {
	case "text":
		if len(e.Text)+len(key.Text) <= 4096 {
			e.Text = e.Text[:e.Cursor] + key.Text + e.Text[e.Cursor:]
			e.Cursor += len(key.Text)
		}
	case "left":
		e.Cursor = e.left()
	case "right":
		e.Cursor = e.right()
	case "home":
		e.Cursor = 0
	case "end":
		e.Cursor = len(e.Text)
	case "backspace":
		if e.Cursor > 0 {
			left := e.left()
			e.Text = e.Text[:left] + e.Text[e.Cursor:]
			e.Cursor = left
		}
	case "delete":
		if e.Cursor < len(e.Text) {
			e.Text = e.Text[:e.Cursor] + e.Text[e.right():]
		}
	case "clear":
		e.Clear()
	case "kill":
		e.Text = e.Text[:e.Cursor]
	}
}
func (e Editor) Display(secret bool) (string, int) {
	if secret {
		return strings.Repeat("*", utf8.RuneCountInString(e.Text)), utf8.RuneCountInString(e.Text[:e.Cursor])
	}
	return e.Text, uniseg.StringWidth(e.Text[:e.Cursor])
}
