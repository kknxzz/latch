package tui

import (
	"strings"
	"testing"
	"time"
	"unicode"

	"github.com/rivo/uniseg"
	"latch.local/client/internal/app"
)

func TestEscapeSanitization(t *testing.T) {
	cases := map[string]string{
		"Hello\x1b[31m red\x1b[0m":                                   "Hello red",
		"before\x1b]52;c;clipboard\aafter":                           "beforeafter",
		"x\x1b]8;;https://attacker.example\x1b\\label\x1b]8;;\x1b\\": "xlabel",
		"x\x1bPpayload\x1b\\y":                                       "xy",
		"a\u009b2Jb\u202e\x00":                                       "ab",
		"a\n\tb":                                                     "a  b",
		"x\x1b]unfinished":                                           "x",
	}
	for input, want := range cases {
		if got := Sanitize(input); got != want {
			t.Fatalf("got %q want %q", got, want)
		}
	}
}
func TestUnicodeEditingAndPastedCommands(t *testing.T) {
	var e Editor
	for _, r := range "A界e\u0301" {
		e.Apply(Key{Kind: "text", Text: string(r)})
	}
	e.Apply(Key{Kind: "left"})
	e.Apply(Key{Kind: "delete"})
	if e.Text != "A界" {
		t.Fatal("grapheme delete failed", e.Text)
	}
	e.Apply(Key{Kind: "backspace"})
	if e.Text != "A" {
		t.Fatal("wide grapheme backspace failed")
	}
	var d Decoder
	keys := d.Feed([]byte("\x1b[200~/quit\nnext\x1b[201~"))
	var pasted Editor
	for _, key := range keys {
		if key.Kind == "submit" || key.Kind == "quit" {
			t.Fatal("paste executed input")
		}
		pasted.Apply(key)
	}
	if pasted.Text != "/quit next" {
		t.Fatalf("paste text %q", pasted.Text)
	}
	for i := 0; i < 5000; i++ {
		e.Apply(Key{Kind: "text", Text: "x"})
	}
	if len(e.Text) > 4096 {
		t.Fatal("unbounded input")
	}
	d.Feed([]byte("\x1b[" + strings.Repeat("1", 100)))
	if len(d.pending) > 32 {
		t.Fatal("unbounded escape buffer")
	}
}
func TestSplitUTF8AndEscape(t *testing.T) {
	var d Decoder
	var keys []Key
	for _, b := range []byte("界\x1b[D") {
		keys = append(keys, d.Feed([]byte{b})...)
	}
	if len(keys) != 2 || keys[0].Text != "界" || keys[1].Kind != "left" {
		t.Fatal("split input failed", keys)
	}
	d.Feed([]byte{27})
	keys = d.Escape()
	if len(keys) != 1 || keys[0].Kind != "cancel" {
		t.Fatal("standalone escape failed")
	}
}
func TestLayoutWidthsAndSecretMasking(t *testing.T) {
	s := app.Snapshot{Server: "https://chat.example", DeviceID: "AABBCC", Nickname: "Levin", Status: "Ready", RoomID: "K7P9X2M4QA", Prompt: "Room PIN: ", Secret: true, Lines: []app.Line{{Time: time.Unix(0, 0), Nickname: "Noah\x1b[2J", Text: "hello\x1b]52;c;secret\a界"}}}
	e := Editor{Text: "123456", Cursor: 6}
	for _, width := range []int{1, 2, 10, 40, 80, 120} {
		for _, height := range []int{3, 6, 24} {
			screen := Layout(s, e, width, height, 0, false)
			if len(screen.Rows) != height {
				t.Fatal("invalid height")
			}
			for _, row := range screen.Rows {
				if uniseg.StringWidth(row) > width {
					t.Fatalf("width %d exceeded by %q", width, row)
				}
				if strings.ContainsAny(row, "\x1b\a") || strings.Contains(row, "123456") {
					t.Fatal("unsanitized text or PIN")
				}
			}
			if screen.CursorX < 0 || screen.CursorX >= width || screen.CursorY < 0 || screen.CursorY >= height {
				t.Fatal("cursor out of bounds")
			}
		}
	}
}
func TestClearedDisplayDoesNotRestoreWelcome(t *testing.T) {
	s := app.Snapshot{Server: "https://chat.example", Status: "Ready", RoomID: "K7P9X2M4QA", ClearID: 1, Prompt: "> "}
	screen := Layout(s, Editor{}, 80, 24, 0, false)
	if strings.Contains(strings.Join(screen.Rows, "\n"), "Welcome to Latch") {
		t.Fatal("cleared viewport restored welcome")
	}
	if !strings.Contains(screen.Rows[0], s.RoomID) {
		t.Fatal("clear removed room header")
	}
}
func FuzzSanitize(f *testing.F) {
	f.Add("hello\x1b[2J")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 65536 {
			return
		}
		out := Sanitize(s)
		for _, r := range out {
			if unicode.IsControl(r) || r == 27 {
				t.Fatal("control sequence survived")
			}
		}
	})
}
