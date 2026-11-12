package tui

import (
	"strings"
	"unicode"
)

// Sanitize strips terminal control strings, controls and directional formatting.
// It is applied at the final rendering boundary, including local nicknames.
func Sanitize(text string) string {
	var out strings.Builder
	out.Grow(len(text))
	state := "text"
	for _, r := range text {
		switch state {
		case "escape":
			switch r {
			case '[':
				state = "csi"
			case ']':
				state = "osc"
			case 'P', '^', '_', 'X':
				state = "string"
			case '(', ')', '*', '+', '-', '.', '/':
				state = "charset"
			default:
				state = "text"
			}
			continue
		case "charset":
			state = "text"
			continue
		case "csi":
			if r >= 0x40 && r <= 0x7e {
				state = "text"
			}
			continue
		case "osc":
			if r == 7 {
				state = "text"
			} else if r == 27 {
				state = "osc_escape"
			}
			continue
		case "string":
			if r == 27 {
				state = "string_escape"
			}
			continue
		case "osc_escape":
			if r == '\\' {
				state = "text"
			} else if r != 27 {
				state = "osc"
			}
			continue
		case "string_escape":
			if r == '\\' {
				state = "text"
			} else if r != 27 {
				state = "string"
			}
			continue
		}
		switch r {
		case 27:
			state = "escape"
			continue
		case 0x9b:
			state = "csi"
			continue
		case 0x9d:
			state = "osc"
			continue
		case 0x90, 0x98, 0x9e, 0x9f:
			state = "string"
			continue
		case '\n', '\r', '\t':
			out.WriteByte(' ')
			continue
		}
		if unicode.IsControl(r) || (unicode.In(r, unicode.Cf) && r != 0x200c && r != 0x200d) || r == 0x2028 || r == 0x2029 {
			continue
		}
		out.WriteRune(r)
	}
	return out.String()
}
