package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type noticeBundle map[string][]byte

func (b noticeBundle) add(name, source string) error {
	if !filepath.IsLocal(name) || strings.Contains(name, "\\") {
		return errors.New("unsafe notice archive path")
	}
	data, err := readRegular(source, 4<<20, false)
	if err != nil {
		return fmt.Errorf("notice %s: %w", name, err)
	}
	if previous, exists := b[name]; exists && !bytes.Equal(previous, data) {
		return fmt.Errorf("conflicting notice %s", name)
	}
	b[name] = data
	return nil
}

func noticeName(name string) bool {
	upper := strings.ToUpper(name)
	for _, prefix := range []string{"LICENSE", "LICENCE", "COPYING", "COPYRIGHT", "NOTICE", "AUTHORS", "PATENTS"} {
		if upper == prefix || strings.HasPrefix(upper, prefix+".") || strings.HasPrefix(upper, prefix+"-") {
			return true
		}
	}
	return false
}

// Preserve original notice files without interpreting SPDX alternatives or
// rewriting copyright holders. Include the full locked graph conservatively,
// including build/test dependencies and inactive platform packages.
func (b noticeBundle) collect(prefix, dir string) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		name := entry.Name()
		if !noticeName(name) && !strings.EqualFold(name, "licenses") {
			continue
		}
		if entry.IsDir() {
			base := filepath.Join(dir, name)
			err := filepath.WalkDir(base, func(path string, nested os.DirEntry, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if nested.IsDir() {
					return nil
				}
				rel, err := filepath.Rel(dir, path)
				if err != nil {
					return err
				}
				if err := b.add(prefix+"/"+filepath.ToSlash(rel), path); err != nil {
					return err
				}
				count++
				return nil
			})
			if err != nil {
				return 0, err
			}
			continue
		}
		if err := b.add(prefix+"/"+name, filepath.Join(dir, name)); err != nil {
			return 0, err
		}
		count++
	}
	return count, nil
}

func noticeCommand(ctx context.Context, dir string, args ...string) ([]byte, error) {
	return noticeCommandEnv(ctx, dir, nil, args...)
}

func noticeCommandEnv(ctx context.Context, dir string, extra map[string]string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Dir = dir
	cmd.Env = buildEnv(os.Environ(), map[string]string{"GOWORK": "off", "GOFLAGS": "", "GOTOOLCHAIN": "local", "RUSTUP_TOOLCHAIN": "1.99.1"}, nil)
	cmd.Env = buildEnv(cmd.Env, extra, nil)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("notice metadata command %s failed: %w", args[0], err)
	}
	if len(output) > 16<<20 {
		return nil, errors.New("notice metadata too large")
	}
	return output, nil
}

func generateNotices(source, component string, check bool) error {
	if !filepath.IsAbs(source) || (component != "client" && component != "server") {
		return errors.New("notices requires an absolute source and client/server component")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	b := noticeBundle{}
	if err := b.add("Latch/LICENSE", filepath.Join(source, "LICENSE")); err != nil {
		return err
	}
	goRoot, err := noticeCommand(ctx, source, "go", "env", "GOROOT")
	if err != nil {
		return err
	}
	if _, err = b.collect("Go", strings.TrimSpace(string(goRoot))); err != nil {
		return err
	}
	// The standard library also incorporates these vendored dependencies.
	vendor := filepath.Join(strings.TrimSpace(string(goRoot)), "src", "vendor")
	if err = filepath.WalkDir(vendor, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !noticeName(entry.Name()) {
			return nil
		}
		rel, err := filepath.Rel(vendor, path)
		if err != nil {
			return err
		}
		return b.add("Go/vendor/"+filepath.ToSlash(rel), path)
	}); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, target := range platforms {
		client := target.Module == "latch.local/client/cmd/latch"
		if client != (component == "client") {
			continue
		}
		entry, cgo := "latch-server", "0"
		if client {
			entry, cgo = "latch", "1"
		}
		packages, err := noticeCommandEnv(ctx, filepath.Join(source, component), map[string]string{"GOOS": target.OS, "GOARCH": target.Arch, "CGO_ENABLED": cgo}, "go", "list", "-mod=readonly", "-deps", "-json=Module", "./cmd/"+entry)
		if err != nil {
			return err
		}
		decoder := json.NewDecoder(bytes.NewReader(packages))
		for {
			var pkg struct {
				Module *struct {
					Path, Version, Dir string
					Main               bool
				}
			}
			if err := decoder.Decode(&pkg); err == io.EOF {
				break
			} else if err != nil {
				return err
			}
			module := pkg.Module
			if module == nil || module.Main || seen[module.Path] {
				continue
			}
			seen[module.Path] = true
			count, err := b.collect("Go/modules/"+module.Path+"@"+module.Version, module.Dir)
			if err != nil || count == 0 {
				return fmt.Errorf("missing Go module notices for %s: %v", module.Path, err)
			}
		}
	}
	if component == "client" {
		metadata, err := noticeCommand(ctx, filepath.Join(source, "client", "crypto-bridge"), "cargo", "metadata", "--locked", "--format-version", "1")
		if err != nil {
			return err
		}
		var graph struct {
			Packages []struct {
				Name, Version string
				License       string   `json:"license"`
				Source        string   `json:"source"`
				Repository    string   `json:"repository"`
				Authors       []string `json:"authors"`
				Manifest      string   `json:"manifest_path"`
				LicenseFile   string   `json:"license_file"`
			} `json:"packages"`
		}
		if err := json.Unmarshal(metadata, &graph); err != nil {
			return err
		}
		var missing []string
		for _, pkg := range graph.Packages {
			if pkg.Name == "latch-crypto" {
				continue
			}
			prefix, dir := "Rust/crates/"+pkg.Name+"@"+pkg.Version, filepath.Dir(pkg.Manifest)
			metadata, err := json.MarshalIndent(pkg, "", "  ")
			if err != nil {
				return err
			}
			// Exclude the local cache path from the public inventory.
			var public map[string]any
			if err := json.Unmarshal(metadata, &public); err != nil {
				return err
			}
			delete(public, "manifest_path")
			public["source_archive"] = "https://crates.io/api/v1/crates/" + pkg.Name + "/" + pkg.Version + "/download"
			if strings.HasPrefix(pkg.Source, "git+") {
				delete(public, "source_archive")
			}
			b[prefix+"/PACKAGE.json"], err = json.MarshalIndent(public, "", "  ")
			if err != nil {
				return err
			}
			count, err := b.collect(prefix, dir)
			if err != nil {
				return err
			}
			if pkg.LicenseFile != "" {
				if err := b.add(prefix+"/DECLARED-LICENSE", filepath.Join(dir, pkg.LicenseFile)); err != nil {
					return err
				}
				count++
			}
			// Patched workspace crates can inherit the repository's license.
			for parent, depth := filepath.Dir(dir), 0; count == 0 && depth < 3 && strings.HasPrefix(pkg.Source, "git+"); parent, depth = filepath.Dir(parent), depth+1 {
				count, err = b.collect(prefix, parent)
				if err != nil {
					return err
				}
			}
			if count == 0 {
				fallback := fallbackNotice(pkg.Name, pkg.Version, pkg.License, dir)
				if fallback == "" {
					missing = append(missing, pkg.Name+"@"+pkg.Version+" ("+pkg.License+", "+pkg.Repository+")")
					continue
				}
				if err := b.add(prefix+"/UPSTREAM-LICENSE", filepath.Join(source, "third_party", "licenses", fallback)); err != nil {
					return err
				}
			}
		}
		if len(missing) != 0 {
			return fmt.Errorf("missing Rust crate notices: %s", strings.Join(missing, "; "))
		}
		sysroot, err := noticeCommand(ctx, source, "rustc", "--print", "sysroot")
		if err != nil {
			return err
		}
		if err := b.add("Rust/standard-library/COPYRIGHT-library.html", filepath.Join(strings.TrimSpace(string(sysroot)), "share", "doc", "rust", "COPYRIGHT-library.html")); err != nil {
			return err
		}
	}
	b["README.txt"] = []byte("Latch " + component + " dependency notices\nOriginal notice files from pinned dependencies and toolchains.\nGo: executable dependencies across supported platforms.\nRust: full locked graph, including build/test and inactive-platform dependencies conservatively.\nThese third-party components retain their own licenses; Latch is MIT licensed.\n")
	archive, err := b.archive()
	if err != nil {
		return err
	}
	path := filepath.Join(source, component, "internal", "licenses", "notices.zip")
	if check {
		current, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(current, archive) {
			return errors.New("embedded dependency notices are stale; regenerate with the pinned toolchains")
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, archive, 0644)
}

// Explicit exceptions for published archives missing their repository license.
// Match the crate's recorded source revision and declared license; an upgrade
// to another revision requires review rather than a guessed replacement text.
func fallbackNotice(name, version, license, dir string) string {
	var vcs struct {
		Git struct {
			SHA string `json:"sha1"`
		} `json:"git"`
	}
	data, err := os.ReadFile(filepath.Join(dir, ".cargo_vcs_info.json"))
	if err != nil || json.Unmarshal(data, &vcs) != nil {
		return ""
	}
	switch {
	case vcs.Git.SHA == "42d68bd49b244b09bd02626c6ffa95e54dc64f91" && strings.HasPrefix(name, "libcrux-") && license == "Apache-2.0":
		return "Libcrux-42d68bd.txt"
	case vcs.Git.SHA == "42d68bd49b244b09bd02626c6ffa95e54dc64f91" && version == "0.8.0" && license == "MPL-2.0" && (name == "hpke-rs" || strings.HasPrefix(name, "hpke-rs-")):
		return "MPL-2.0.txt"
	case vcs.Git.SHA == "8a8f83b4b61fc45f28facec25e914992b3465de6" && name == "openmls" && version == "0.9.2" && license == "MIT":
		return "OpenMLS-0.9.2.txt"
	case vcs.Git.SHA == "3a3e35de3feeca8f6605143c464d5452ae584d43" && name == "openmls_serialization_helpers" && version == "0.1.0" && license == "MIT":
		return "OpenMLS-serialization-0.1.0.txt"
	}
	return ""
}

func (b noticeBundle) archive() ([]byte, error) {
	var buffer bytes.Buffer
	w := zip.NewWriter(&buffer)
	names := make([]string, 0, len(b))
	for name := range b {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate}
		header.SetMode(0644)
		header.Modified = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
		file, err := w.CreateHeader(header)
		if err != nil {
			return nil, err
		}
		if _, err := file.Write(b[name]); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
