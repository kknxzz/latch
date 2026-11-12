package config

import "testing"

func TestURLNormalization(t *testing.T) {
	cases := []struct {
		raw, endpoint string
		dev           bool
		want          string
		valid         bool
	}{
		{"https://chat.example/", "", false, "https://chat.example", true},
		{"wss://chat.example:8443", "/c/", false, "https://chat.example:8443", true},
		{"http://127.0.0.1:8080", "", true, "http://127.0.0.1:8080", true},
		{"ws://[::1]:8080", "", true, "http://[::1]:8080", true},
		{"http://chat.example", "", true, "", false},
		{"http://127.0.0.1:8080", "", false, "", false},
		{"https://user:password@chat.example", "", false, "", false},
		{"https://chat.example/path", "", false, "", false},
		{"https://chat.example?pin=123456", "", false, "", false},
		{"https://chat.example", "//other.example/c/", false, "", false},
		{"https://chat.example", "/%2fc/", false, "", false},
		{"chat.example", "", false, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.raw+tc.endpoint, func(t *testing.T) {
			got, _, err := Normalize(tc.raw, tc.endpoint, tc.dev)
			if (err == nil) != tc.valid || got != tc.want {
				t.Fatalf("got=%q err=%v", got, err)
			}
		})
	}
}
func TestSecureWebSocket(t *testing.T) {
	c := Config{ServerURL: "https://chat.example", Endpoint: "/c/"}
	s, err := c.WebSocketURL()
	if err != nil || s != "wss://chat.example/c/" {
		t.Fatal(s, err)
	}
}
