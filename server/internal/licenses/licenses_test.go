package licenses

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestOfflineExportPreservesNoticesAndExistingFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notices.zip")
	if err := Run([]string{"--output", path}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, archive) {
		t.Fatal("export changed notice bytes", err)
	}
	r, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, file := range r.File {
		if !filepath.IsLocal(file.Name) {
			t.Fatal("unsafe notice path")
		}
		reader, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(reader)
		reader.Close()
		if err != nil || len(content) == 0 || bytes.Contains(content, []byte("/Users/levin/")) {
			t.Fatal("invalid or machine-specific notice", file.Name, err)
		}
		found[file.Name] = true
	}
	for _, name := range []string{"README.txt", "Latch/LICENSE", "Go/LICENSE"} {
		if !found[name] {
			t.Fatal("missing attribution", name)
		}
	}
	if err := os.WriteFile(path, []byte("keep existing content"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Run([]string{"--output", path}); err == nil {
		t.Fatal("existing output overwritten")
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "keep existing content" {
		t.Fatal("existing output changed", err)
	}
}
