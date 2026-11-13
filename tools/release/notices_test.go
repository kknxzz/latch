package main

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestNoticeCollectionAndDeterministicArchive(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "LICENSE"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "LICENSE", "MIT.LICENSE"), []byte("Original attribution\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "src.go"), []byte("private source path"), 0600); err != nil {
		t.Fatal(err)
	}
	b := noticeBundle{}
	count, err := b.collect("example@1.0", dir)
	if err != nil || count != 1 {
		t.Fatal(count, err)
	}
	first, err := b.archive()
	if err != nil {
		t.Fatal(err)
	}
	second, err := b.archive()
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("archive is not reproducible", err)
	}
	r, err := zip.NewReader(bytes.NewReader(first), int64(len(first)))
	if err != nil || len(r.File) != 1 {
		t.Fatal("invalid notice archive", err)
	}
	if r.File[0].Name != "example@1.0/LICENSE/MIT.LICENSE" {
		t.Fatal("notice path changed")
	}
	f, err := r.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil || string(data) != "Original attribution\n" {
		t.Fatal("notice text changed", err)
	}
	if err := b.add("../escape", filepath.Join(dir, "src.go")); err == nil {
		t.Fatal("unsafe archive path accepted")
	}
	if err := os.Symlink(filepath.Join(dir, "src.go"), filepath.Join(dir, "NOTICE")); err != nil {
		t.Fatal(err)
	}
	if _, err := b.collect("other", dir); err == nil {
		t.Fatal("symlink notice accepted")
	}
}

func TestNoticeFallbackRequiresReviewedRevisionAndLicense(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".cargo_vcs_info.json")
	if err := os.WriteFile(path, []byte(`{"git":{"sha1":"8a8f83b4b61fc45f28facec25e914992b3465de6"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if fallbackNotice("openmls", "0.9.2", "MIT", dir) != "OpenMLS-0.9.2.txt" {
		t.Fatal("reviewed source not recognized")
	}
	if fallbackNotice("openmls", "0.9.3", "MIT", dir) != "" || fallbackNotice("openmls", "0.9.2", "Apache-2.0", dir) != "" {
		t.Fatal("unreviewed declaration accepted")
	}
	if err := os.WriteFile(path, []byte(`{"git":{"sha1":"unknown"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if fallbackNotice("openmls", "0.9.2", "MIT", dir) != "" {
		t.Fatal("unreviewed source accepted")
	}
}
