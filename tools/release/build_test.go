package main

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sourceArchive(t *testing.T, headers ...*tar.Header) []byte {
	t.Helper()
	var data bytes.Buffer
	w := tar.NewWriter(&data)
	for _, h := range headers {
		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg && h.Size > 0 {
			if _, err := w.Write(bytes.Repeat([]byte("a"), int(h.Size))); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}
func TestSourceExportBoundsAndPermissions(t *testing.T) {
	epoch := time.Unix(1700000000, 0)
	data := sourceArchive(t, &tar.Header{Name: "pax_global_header", Typeflag: tar.TypeXGlobalHeader, PAXRecords: map[string]string{"comment": strings.Repeat("a", 40)}}, &tar.Header{Name: "client/", Typeflag: tar.TypeDir, Mode: 0755}, &tar.Header{Name: "client/main.go", Typeflag: tar.TypeReg, Size: 3, Mode: 0644, ModTime: epoch}, &tar.Header{Name: "scripts/install.sh", Typeflag: tar.TypeReg, Size: 4, Mode: 0755, ModTime: epoch})
	dir := t.TempDir()
	if err := extractSource(bytes.NewReader(data), dir); err != nil {
		t.Fatal(err)
	}
	for name, mode := range map[string]os.FileMode{"client/main.go": 0600, "scripts/install.sh": 0700} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Mode().Perm() != mode || !info.ModTime().Equal(epoch) {
			t.Fatal("export lost mode/time normalization", name, err)
		}
	}
	for _, h := range []*tar.Header{
		{Name: "../escape", Typeflag: tar.TypeReg},
		{Name: "/escape", Typeflag: tar.TypeReg},
		{Name: "client/../../escape", Typeflag: tar.TypeReg},
		{Name: "client\\escape", Typeflag: tar.TypeReg},
		{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "../escape"},
		{Name: "link", Typeflag: tar.TypeLink, Linkname: "../escape"},
	} {
		t.Run(strings.ReplaceAll(h.Name, "/", "_"), func(t *testing.T) {
			if err := extractSource(bytes.NewReader(sourceArchive(t, h)), t.TempDir()); err == nil {
				t.Fatal("unsafe archive accepted", h)
			}
		})
	}
	duplicate := sourceArchive(t, &tar.Header{Name: "same", Typeflag: tar.TypeReg}, &tar.Header{Name: "same", Typeflag: tar.TypeReg})
	if extractSource(bytes.NewReader(duplicate), t.TempDir()) == nil {
		t.Fatal("duplicate file silently overwrote source")
	}
}
func TestBuildEnvironmentOverrides(t *testing.T) {
	env := buildEnv([]string{"GOFLAGS=old", "RUSTC_WRAPPER=unexpected", "KEEP=value"}, map[string]string{"GOFLAGS": "", "SOURCE_DATE_EPOCH": "1"}, []string{"RUSTC_WRAPPER"})
	joined := strings.Join(env, "\n")
	if strings.Contains(joined, "old") || strings.Contains(joined, "unexpected") || !strings.Contains(joined, "KEEP=value") || !strings.Contains(joined, "GOFLAGS=\n") {
		t.Fatal("ambient build override leaked", env)
	}
}
