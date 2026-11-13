package tests

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"latch.local/server/internal/auth"
)

// Offline, synthetic benchmark setup only. No production flag or endpoint can
// invoke this helper. Every measured connection still proves its private key.
func TestPreparePerformanceFixture(t *testing.T) {
	input, state := os.Getenv("LATCH_PERF_FIXTURE_INPUT"), os.Getenv("LATCH_PERF_FIXTURE_STATE")
	if input == "" {
		t.Skip("explicit offline benchmark fixture only")
	}
	if !filepath.IsAbs(input) || !filepath.IsAbs(state) {
		t.Fatal("fixture paths must be absolute")
	}
	if _, err := os.Lstat(state); !os.IsNotExist(err) {
		t.Fatal("refusing existing state")
	}
	info, err := os.Lstat(input)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 1<<20 {
		t.Fatal("unsafe fixture input")
	}
	data, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	var devices []struct {
		UUID      string `json:"uuid"`
		PublicKey []byte `json:"public_key"`
		Nickname  string `json:"nickname"`
	}
	if err = json.Unmarshal(data, &devices); err != nil || len(devices) < 1 || len(devices) > 100 {
		t.Fatal("invalid fixture inventory")
	}
	store, err := auth.Open(filepath.Join(state, "state.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, device := range devices {
		code, _, err := store.GenerateCode()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = store.Enroll(code, device.UUID, device.PublicKey, device.Nickname, "synthetic benchmark fixture"); err != nil {
			t.Fatal(err)
		}
	}
	file, err := os.OpenFile(input+".server-id", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err = file.WriteString(store.ServerID()); err != nil {
		t.Fatal(err)
	}
}
