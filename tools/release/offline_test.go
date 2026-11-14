package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// This exercises verification and dispatch without installing a service. The
// synthetic platform tools and installer cannot modify the host's systemd state.
func TestOfflineServerBootstrap(t *testing.T) {
	base := t.TempDir()
	keys := initialize(t)
	key, err := loadPrivate(keys, "targets")
	if err != nil {
		t.Fatal(err)
	}
	assets := filepath.Join(base, "assets")
	bin := filepath.Join(base, "tools")
	for _, dir := range []string{assets, bin} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	writeExecutable := func(path, content string) {
		put(t, path, []byte(content))
		if err := os.Chmod(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	writeExecutable(filepath.Join(bin, "id"), "#!/bin/sh\necho 0\n")
	writeExecutable(filepath.Join(bin, "uname"), "#!/bin/sh\ncase \"$1\" in -s) echo Linux;; -m) echo "+runtime.GOARCH+";; *) exit 1;; esac\n")
	artifact := "latch-server-linux-" + runtime.GOARCH
	script := get(t, "../../client/scripts/install.sh")
	put(t, filepath.Join(assets, "start.sh"), script)
	put(t, filepath.Join(assets, artifact), []byte("#!/bin/sh\n[ \"$1\" = version ] || exit 1\necho 'Latch Server 0.1.0'\n"))
	put(t, filepath.Join(assets, "server-install.sh"), []byte("#!/bin/sh\n[ \"$1\" = install ] || exit 1\n[ \"$2\" = --binary ] || exit 1\n[ -x \"$3\" ] || exit 1\necho 'Verified offline dispatch'\n"))
	put(t, filepath.Join(assets, "latch-server.service"), []byte("# Synthetic service; never installed.\n"))
	manifest := fmt.Sprintf("Latch-Release 1\nVersion 0.1.0\nExpires %d\nSource %s\n", time.Now().Add(time.Hour).Unix(), strings.Repeat("a", 40))
	for _, name := range []string{"start.sh", artifact, "server-install.sh", "latch-server.service"} {
		manifest += fmt.Sprintf("SHA256 %x %s\n", sha256.Sum256(get(t, filepath.Join(assets, name))), name)
	}
	put(t, filepath.Join(assets, "manifest.txt"), []byte(manifest))
	sig, err := signFile(key, []byte(manifest))
	if err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(assets, "manifest.sig"), sig)
	run := func() (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "sh", filepath.Join(assets, "start.sh"), "--component", "server", "--offline-directory", assets, "--publisher-key", filepath.Join(keys, "publisher.pub"))
		cmd.Env = append(os.Environ(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if out, err := run(); err != nil || !strings.Contains(out, "Verified offline dispatch") {
		t.Fatal("offline verification", err, out)
	}
	for _, name := range []string{artifact, "server-install.sh", "latch-server.service", "manifest.txt"} {
		t.Run("Tamper_"+name, func(t *testing.T) {
			path := filepath.Join(assets, name)
			original := get(t, path)
			defer put(t, path, original)
			put(t, path, []byte("tampered"))
			if out, err := run(); err == nil || strings.Contains(out, "Verified offline dispatch") {
				t.Fatal("accepted tampering", err, out)
			}
		})
	}
	t.Run("RejectSymlink", func(t *testing.T) {
		path := filepath.Join(assets, artifact)
		original := get(t, path)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(assets, "start.sh"), path); err != nil {
			t.Fatal(err)
		}
		defer func() { os.Remove(path); put(t, path, original) }()
		if out, err := run(); err == nil || !strings.Contains(out, "Missing regular release file") {
			t.Fatal("accepted symlink", err, out)
		}
	})
}
