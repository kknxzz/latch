package tui

import (
	"fmt"
	"strings"

	"github.com/rivo/uniseg"
	"latch.local/client/internal/app"
	"latch.local/client/internal/identity"
)

type Screen struct {
	Rows             []string
	CursorX, CursorY int
}

func clip(text string, width int) string {
	if width <= 0 {
		return ""
	}
	var out strings.Builder
	g := uniseg.NewGraphemes(text)
	used := 0
	for g.Next() {
		w := g.Width()
		if used+w > width {
			break
		}
		used += w
		out.WriteString(g.Str())
	}
	return out.String()
}
func pad(text string, width int) string {
	text = clip(text, width)
	return text + strings.Repeat(" ", max(0, width-uniseg.StringWidth(text)))
}
func wrap(text string, width int) []string {
	if width < 1 {
		return nil
	}
	var lines []string
	var line strings.Builder
	used := 0
	g := uniseg.NewGraphemes(text)
	for g.Next() {
		w := g.Width()
		if used+w > width && used > 0 {
			lines = append(lines, line.String())
			line.Reset()
			used = 0
		}
		if w > width {
			continue
		}
		line.WriteString(g.Str())
		used += w
	}
	lines = append(lines, line.String())
	return lines
}
func Layout(s app.Snapshot, e Editor, width, height, scroll int, membersFocus bool) Screen {
	width = max(1, min(width, 500))
	height = max(3, min(height, 200))
	rows := make([]string, height)
	title := "Latch"
	if s.RoomID != "" {
		title += " | " + Sanitize(s.RoomID)
		if s.Host {
			title += " [Host]"
		}
	}
	rows[0] = clip(title+"  ·  "+Sanitize(s.Status), width)
	rows[1] = clip(Sanitize(s.Server)+"  ·  Identity: "+Sanitize(s.DeviceID)+"  ·  "+Sanitize(s.Nickname), width)
	if height < 6 {
		rows[height-1] = clip("> ", width)
		return Screen{Rows: rows, CursorX: min(2, width-1), CursorY: height - 1}
	}
	rows[2] = strings.Repeat("─", width)
	showMembers := len(s.Members) > 0 && (width >= 88 || membersFocus)
	memberWidth := 0
	if showMembers {
		memberWidth = min(29, width/2)
	}
	chatWidth := width
	if memberWidth > 0 {
		chatWidth -= memberWidth + 3
	}
	available := height - 6
	scroll = max(0, min(scroll, 10000))
	// Walk backwards only as far as the visible viewport and requested scroll.
	// A narrow terminal must not expand the entire 2 MiB buffer into row objects.
	var reversed []string
	for index := len(s.Lines) - 1; index >= 0 && len(reversed) < scroll+available; index-- {
		line := s.Lines[index]
		prefix := "[" + line.Time.Format("15:04") + "] "
		if line.System {
			prefix += "* "
		} else {
			prefix += "<" + Sanitize(line.Nickname) + "> "
		}
		wrapped := wrap(prefix+Sanitize(line.Text), max(1, chatWidth))
		for i := len(wrapped) - 1; i >= 0 && len(reversed) < scroll+available; i-- {
			reversed = append(reversed, wrapped[i])
		}
	}
	if len(s.Lines) == 0 {
		reversed = []string{"Use /help for commands.", "Welcome to Latch."}
	}
	var visible []string
	for i := min(len(reversed), scroll+available) - 1; i >= scroll; i-- {
		visible = append(visible, reversed[i])
	}
	for i := 0; i < available; i++ {
		text := ""
		if i < len(visible) {
			text = visible[i]
		}
		row := pad(text, chatWidth)
		if memberWidth > 0 {
			member := ""
			if i == 0 {
				member = fmt.Sprintf("Members (%d)", len(s.Members))
			} else if i-1 < len(s.Members) {
				m := s.Members[i-1]
				name := Sanitize(m.Nickname)
				if name == "" {
					name = m.UUID[:min(8, len(m.UUID))]
				}
				if m.UUID == s.HostUUID {
					name = "@" + name
				}
				short := (identity.Identity{PublicKey: m.PublicKey}).DeviceID()
				member = name + " " + short
			}
			row += " │ " + clip(member, memberWidth)
		}
		rows[i+3] = clip(row, width)
	}
	rows[height-3] = strings.Repeat("─", width)
	display, cursor := e.Display(s.Secret)
	prompt := Sanitize(s.Prompt)
	promptWidth := uniseg.StringWidth(prompt)
	// Keep the cursor visible without splitting graphemes. An offscreen prefix is
	// replaced by a single marker; normal input remains one row.
	offset := max(0, cursor-max(1, width-promptWidth-2))
	if offset > 0 {
		g := uniseg.NewGraphemes(display)
		used := 0
		for g.Next() {
			_, end := g.Positions()
			used += g.Width()
			if used >= offset {
				display = display[end:]
				cursor -= used
				break
			}
		}
		prompt = "‹ "
		promptWidth = 2
	}
	rows[height-2] = clip(prompt+display, width)
	rows[height-1] = clip("Tab Members  ·  PgUp/PgDn Scroll  ·  /help  ·  Ctrl+C Exit", width)
	return Screen{Rows: rows, CursorX: min(width-1, max(0, promptWidth+cursor)), CursorY: height - 2}
}

// Diff renders changed rows only; a resize invalidates the previous frame.
func Diff(previous []string, screen Screen, color bool) string {
	var out strings.Builder
	out.WriteString("\x1b[?25l")
	for i, row := range screen.Rows {
		if i < len(previous) && previous[i] == row {
			continue
		}
		fmt.Fprintf(&out, "\x1b[%d;1H\x1b[2K", i+1)
		if color {
			if i == 0 {
				out.WriteString("\x1b[38;5;109m")
			} else if i == 1 || i == len(screen.Rows)-1 {
				out.WriteString("\x1b[38;5;245m")
			}
		}
		out.WriteString(row)
		if color {
			out.WriteString("\x1b[0m")
		}
	}
	fmt.Fprintf(&out, "\x1b[%d;%dH\x1b[?25h", screen.CursorY+1, screen.CursorX+1)
	return out.String()
}
