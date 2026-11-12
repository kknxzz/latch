package main

import (
	"archive/tar"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

type buildOptions struct{ Source, Output, Root, Version, Commit, Component string }
type buildEnvironment struct {
	SourceCommit string `json:"source_commit"`
	SourceEpoch  int64  `json:"source_epoch"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	Go           string `json:"go"`
	Rust         string `json:"rust,omitempty"`
	CCompiler    string `json:"c_compiler,omitempty"`
	SDK          string `json:"sdk,omitempty"`
}

func buildNative(b buildOptions) error {
	if !filepath.IsAbs(b.Source) || !filepath.IsAbs(b.Output) || !filepath.IsAbs(b.Root) {
		return errors.New("source, output and public root paths must be absolute")
	}
	if !validVersion(b.Version) || len(b.Commit) != 40 || strings.Trim(b.Commit, "0123456789abcdef") != "" {
		return errors.New("a stable version and exact source commit are required")
	}
	if b.Component != "all" && b.Component != "client" && b.Component != "server" {
		return errors.New("component must be client, server or all")
	}
	if (runtime.GOOS != "linux" && runtime.GOOS != "darwin") || (runtime.GOARCH != "arm64" && runtime.GOARCH != "amd64") || (b.Component == "server" && runtime.GOOS != "linux") {
		return errors.New("build on a supported native target; server releases require Linux")
	}
	root, err := readRegular(b.Root, 65536, false)
	if err != nil {
		return err
	}
	anchor, err := metadata.Root().FromBytes(root)
	if err != nil || anchor.VerifyDelegate("root", anchor) != nil || !anchor.Signed.Expires.After(time.Now()) {
		return errors.New("build requires a current self-verified public root")
	}
	if err = protectedDir(b.Output); err != nil {
		return err
	}
	entries, err := os.ReadDir(b.Output)
	if err != nil || len(entries) != 0 {
		return errors.New("build output must be an empty private directory")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	baseEnv := buildEnv(os.Environ(), map[string]string{"GOTOOLCHAIN": "local", "GOENV": "off", "GOFLAGS": "", "GOWORK": "off", "RUSTUP_TOOLCHAIN": "1.99.1"}, nil)
	goVersion, err := capture(ctx, b.Source, baseEnv, "go", "env", "GOVERSION")
	if err != nil || goVersion != "go1.27.4" {
		return errors.New("release build requires Go 1.27.4")
	}
	commit, err := capture(ctx, b.Source, baseEnv, "git", "rev-parse", "--verify", b.Commit+"^{commit}")
	if err != nil || commit != b.Commit {
		return errors.New("reviewed source commit is unavailable")
	}
	stamp, err := capture(ctx, b.Source, baseEnv, "git", "show", "-s", "--format=%ct", b.Commit)
	if err != nil {
		return err
	}
	epoch, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil || epoch < 1 {
		return errors.New("invalid source commit timestamp")
	}
	environment := buildEnvironment{SourceCommit: b.Commit, SourceEpoch: epoch, OS: runtime.GOOS, Arch: runtime.GOARCH, Go: goVersion}
	if b.Component != "server" {
		rust, err := capture(ctx, b.Source, baseEnv, "rustc", "--version")
		if err != nil || !strings.HasPrefix(rust, "rustc 1.99.1 ") {
			return errors.New("client release build requires Rust 1.99.1")
		}
		environment.Rust = rust
		compiler, err := capture(ctx, b.Source, baseEnv, "cc", "--version")
		if err != nil {
			return errors.New("client release build requires a native C compiler")
		}
		environment.CCompiler = strings.Split(compiler, "\n")[0]
		if runtime.GOOS == "darwin" {
			environment.SDK, err = capture(ctx, b.Source, baseEnv, "xcrun", "--show-sdk-version")
			if err != nil {
				return errors.New("macOS build requires a selected SDK")
			}
		}
	}
	work, err := os.MkdirTemp("", "latch-release-build-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	source := filepath.Join(work, "source")
	if err = os.Mkdir(source, 0700); err != nil {
		return err
	}
	if err = exportSource(ctx, b.Source, b.Commit, source); err != nil {
		return err
	}
	for _, path := range []string{filepath.Join(work, "go-cache"), filepath.Join(work, "go-tmp")} {
		if err = os.Mkdir(path, 0700); err != nil {
			return err
		}
	}
	// Normalize paths in native diagnostics and generated C as well as Go source.
	// Each invocation starts with fresh Go and Cargo compilation caches. Only
	// downloaded module/crate sources may be shared between independent builds.
	cflags := "-O2 -g0 " + strconv.Quote("-ffile-prefix-map="+work+"=/build") + " " + strconv.Quote("-ffile-prefix-map="+source+"=/latch") + " " + strconv.Quote("-fdebug-prefix-map="+work+"=/build")
	rustflags := []string{"--remap-path-prefix=" + work + "=/build", "--remap-path-prefix=" + source + "=/latch"}
	for _, pair := range [][2]string{{os.Getenv("CARGO_HOME"), "/cargo-home"}, {os.Getenv("RUSTUP_HOME"), "/rustup-home"}} {
		if pair[0] != "" {
			rustflags = append(rustflags, "--remap-path-prefix="+pair[0]+"="+pair[1])
		}
	}
	// Cargo's default home also needs remapping if CARGO_HOME is not overridden.
	if os.Getenv("CARGO_HOME") == "" {
		if home, e := os.UserHomeDir(); e == nil {
			rustflags = append(rustflags, "--remap-path-prefix="+filepath.Join(home, ".cargo")+"=/cargo-home")
		}
	}
	env := buildEnv(baseEnv, map[string]string{
		"SOURCE_DATE_EPOCH": stamp, "TZ": "UTC", "LC_ALL": "C", "GOOS": runtime.GOOS, "GOARCH": runtime.GOARCH, "GOAMD64": "v1", "GOARM64": "v8.0", "GOEXPERIMENT": "",
		"GOCACHE": filepath.Join(work, "go-cache"), "GOTMPDIR": filepath.Join(work, "go-tmp"), "CGO_ENABLED": "1", "CC": "cc", "CGO_CFLAGS": cflags, "CGO_CPPFLAGS": "", "CGO_CXXFLAGS": cflags, "CGO_LDFLAGS": "",
		"RUSTFLAGS": "", "CARGO_ENCODED_RUSTFLAGS": strings.Join(rustflags, "\x1f"), "CARGO_TARGET_DIR": filepath.Join(source, "client", "crypto-bridge", "target"), "CARGO_INCREMENTAL": "0", "CARGO_NET_GIT_FETCH_WITH_CLI": "true",
	}, []string{"RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTC_BOOTSTRAP", "RUSTDOCFLAGS"})
	if b.Component != "server" {
		if err = runBuild(ctx, source, env, "sh", "scripts/build-crypto.sh"); err != nil {
			return err
		}
	}
	for _, target := range platforms {
		if target.OS != runtime.GOOS || target.Arch != runtime.GOARCH {
			continue
		}
		client := target.Module == "latch.local/client/cmd/latch"
		if (client && b.Component == "server") || (!client && b.Component == "client") {
			continue
		}
		flags := "-buildid= -s -w -X main.version=" + b.Version
		module, entry := "server", "latch-server"
		targetEnv := buildEnv(env, map[string]string{"CGO_ENABLED": "0"}, nil)
		if client {
			module, entry = "client", "latch"
			targetEnv = env
			flags += " -X latch.local/client/internal/update.rootBase64=" + base64.StdEncoding.EncodeToString(root)
		}
		binary := filepath.Join(b.Output, target.Name)
		if err = runBuild(ctx, filepath.Join(source, module), targetEnv, "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags", flags, "-o", binary, "./cmd/"+entry); err != nil {
			return err
		}
		if err = inspect(binary, target.Name, b.Root, b.Version, b.Commit); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(environment, "", "  ")
	if err != nil {
		return err
	}
	return writeNew(filepath.Join(b.Output, "build-environment.json"), append(data, '\n'), 0644)
}

func buildEnv(base []string, overrides map[string]string, remove []string) []string {
	discard := map[string]bool{}
	for _, name := range remove {
		discard[name] = true
	}
	result := make([]string, 0, len(base)+len(overrides))
	for _, value := range base {
		name, _, _ := strings.Cut(value, "=")
		if _, ok := overrides[name]; !ok && !discard[name] {
			result = append(result, value)
		}
	}
	names := make([]string, 0, len(overrides))
	for name := range overrides {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		result = append(result, name+"="+overrides[name])
	}
	return result
}
func capture(ctx context.Context, dir string, env []string, program string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Dir = dir
	cmd.Env = env
	var output limitedOutput
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s failed: %w", program, err)
	}
	return strings.TrimSpace(output.String()), nil
}
func runBuild(ctx context.Context, dir string, env []string, program string, args ...string) error {
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s build failed: %w", program, err)
	}
	return nil
}
func exportSource(ctx context.Context, repository, commit, destination string) error {
	cmd := exec.CommandContext(ctx, "git", "-C", repository, "archive", "--format=tar", commit)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	defer pipe.Close()
	cmd.Stderr = io.Discard
	if err = cmd.Start(); err != nil {
		return err
	}
	err = extractSource(pipe, destination)
	if err != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if err != nil {
		return err
	}
	if waitErr != nil {
		return errors.New("source archive export failed")
	}
	return nil
}
func extractSource(reader io.Reader, destination string) error {
	const limit = 128 << 20
	bounded := &io.LimitedReader{R: reader, N: limit + 1}
	archive := tar.NewReader(bounded)
	for count := 0; ; count++ {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if count >= 10000 || header.Size < 0 || header.Size > 16<<20 {
			return errors.New("source archive exceeds build limits")
		}
		name := filepath.FromSlash(header.Name)
		clean := filepath.Clean(name)
		if clean == "." || filepath.IsAbs(name) || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) || strings.ContainsAny(name, "\\\x00") {
			return errors.New("unsafe source archive path")
		}
		path := filepath.Join(destination, clean)
		switch header.Typeflag {
		case tar.TypeXGlobalHeader:
			// git archive records the commit as global PAX metadata. It creates
			// no filesystem entry; later file paths are still validated below.
			continue
		case tar.TypeDir:
			if err = os.MkdirAll(path, 0700); err != nil {
				return err
			}
		case tar.TypeReg:
			if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				return err
			}
			mode := os.FileMode(0600)
			if header.Mode&0111 != 0 {
				mode = 0700
			}
			file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
			if err != nil {
				return err
			}
			_, copyErr := io.CopyN(file, archive, header.Size)
			closeErr := file.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
			if err = os.Chtimes(path, header.ModTime, header.ModTime); err != nil {
				return err
			}
		default:
			return errors.New("source archives may contain only regular files and directories")
		}
	}
	if _, err := io.Copy(io.Discard, bounded); err != nil {
		return err
	}
	if bounded.N <= 0 {
		return errors.New("source archive exceeds size limit")
	}
	return nil
}
