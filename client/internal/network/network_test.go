package network

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"latch.local/client/internal/config"
	"latch.local/client/internal/identity"
)

func TestRejectInvalidTLSAndRedirects(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer target.Close()
	client := New(config.Config{ServerURL: target.URL})
	defer client.Close()
	if _, err := client.Info(context.Background()); err == nil {
		t.Fatal("untrusted TLS certificate accepted")
	}
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1", http.StatusFound)
	}))
	defer redirect.Close()
	client = New(config.Config{ServerURL: redirect.URL, Development: true})
	defer client.Close()
	if _, err := client.Info(context.Background()); err == nil {
		t.Fatal("redirect accepted")
	}
}
func TestServerIdentityPinning(t *testing.T) {
	expected, _ := identity.NewUUID()
	other, _ := identity.NewUUID()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"v":1,"server_id":"` + other + `","limits":{"connections":100,"rooms":20,"members":16,"message_bytes":4096}}`))
	}))
	defer server.Close()
	client := New(config.Config{ServerURL: server.URL, Development: true, ServerID: expected})
	defer client.Close()
	if _, err := client.Info(context.Background()); err != ErrServerChanged {
		t.Fatal("server identity changed silently", err)
	}
}
