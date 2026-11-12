package main

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	"golang.org/x/sys/unix"
)

type publication struct {
	Keys, Artifacts, Output, Version, Commit, ClientScript, ServerScript, ServerUnit, License string
	Expires                                                                                   time.Time
}
type artifact struct{ Name, Module, OS, Arch string }

var platforms = []artifact{
	{"latch-darwin-arm64", "latch.local/client/cmd/latch", "darwin", "arm64"},
	{"latch-darwin-amd64", "latch.local/client/cmd/latch", "darwin", "amd64"},
	{"latch-linux-arm64", "latch.local/client/cmd/latch", "linux", "arm64"},
	{"latch-linux-amd64", "latch.local/client/cmd/latch", "linux", "amd64"},
	{"latch-server-linux-arm64", "latch.local/server/cmd/latch-server", "linux", "arm64"},
	{"latch-server-linux-amd64", "latch.local/server/cmd/latch-server", "linux", "amd64"},
}

func validVersion(value string) bool {
	if len(value) > 40 {
		return false
	}
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}
	return true
}
func atomicFile(path string, data []byte) error { return atomicMode(path, data, 0644) }
func atomicMode(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".release-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err = file.Chmod(mode); err != nil {
		return err
	}
	if _, err = file.Write(data); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Rename(file.Name(), path); err != nil {
		return err
	}
	folder, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer folder.Close()
	return folder.Sync()
}
func ensurePublicDir(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 || !owned(info) {
		return errors.New("unsafe public release directory")
	}
	return nil
}

// Resolve aliases through existing ancestors before comparing directory trees.
func resolvedPath(path string) (string, error) {
	path = filepath.Clean(path)
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved, nil
	}
	if !errors.Is(err, os.ErrNotExist) || filepath.Dir(path) == path {
		return "", err
	}
	parent, err := resolvedPath(filepath.Dir(path))
	return filepath.Join(parent, filepath.Base(path)), err
}
func overlapping(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+string(os.PathSeparator)) || strings.HasPrefix(b, a+string(os.PathSeparator))
}
func reference(version int64, data []byte) *metadata.MetaFiles {
	sum := sha256.Sum256(data)
	return &metadata.MetaFiles{Version: version, Length: int64(len(data)), Hashes: metadata.Hashes{"sha256": sum[:]}}
}
func publish(p publication) error {
	if !filepath.IsAbs(p.Output) || !filepath.IsAbs(p.Artifacts) {
		return errors.New("artifact and public output directories must be explicit absolute paths")
	}
	if !filepath.IsAbs(p.Keys) {
		return errors.New("key directory must be absolute")
	}
	keysAbs, err := resolvedPath(p.Keys)
	if err != nil {
		return err
	}
	outputAbs, err := resolvedPath(p.Output)
	if err != nil {
		return err
	}
	if overlapping(keysAbs, outputAbs) {
		return errors.New("signing keys and public output must have separate directory trees")
	}
	artifactsAbs, err := resolvedPath(p.Artifacts)
	if err != nil {
		return err
	}
	if overlapping(artifactsAbs, outputAbs) {
		return errors.New("build artifacts and public output must have separate directory trees")
	}
	if !validVersion(p.Version) || len(p.Commit) != 40 {
		return errors.New("a stable numeric version and 40-character source commit are required")
	}
	for _, c := range p.Commit {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return errors.New("invalid source commit")
		}
	}
	now := time.Now().UTC()
	if !p.Expires.After(now) || p.Expires.After(now.Add(8*24*time.Hour)) {
		return errors.New("manifest expiry must be in the next eight days")
	}
	if err := protectedDir(p.Keys); err != nil {
		return err
	}
	fd, err := unix.Open(filepath.Join(p.Keys, "publish.lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var lockInfo unix.Stat_t
	if err = unix.Fstat(fd, &lockInfo); err != nil || lockInfo.Mode&unix.S_IFMT != unix.S_IFREG || lockInfo.Mode&0777 != 0600 || lockInfo.Uid != uint32(os.Geteuid()) {
		return errors.New("unsafe publication lock")
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.New("another publication is running")
	}
	rootBytes, err := readRegular(filepath.Join(p.Keys, "root.json"), 65536, false)
	if err != nil {
		return err
	}
	root, err := metadata.Root().FromBytes(rootBytes)
	if err != nil {
		return err
	}
	if err = root.VerifyDelegate("root", root); err != nil {
		return err
	}
	if !root.Signed.Expires.After(p.Expires) || !root.Signed.ConsistentSnapshot {
		return errors.New("publisher root must be current and require consistent snapshots")
	}
	rootRole := root.Signed.Roles["root"]
	if rootRole == nil || rootRole.Threshold < 2 || len(rootRole.KeyIDs) < 3 {
		return errors.New("publisher root requires at least a two-of-three offline key threshold")
	}
	version := int64(1)
	counterPath := filepath.Join(p.Keys, "sequence")
	if data, e := readRegular(counterPath, 64, true); e == nil {
		previous, e := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		if e != nil || previous < 1 || previous == 1<<63-1 {
			return errors.New("invalid publication sequence")
		}
		version = previous + 1
	} else if _, e = os.Lstat(counterPath); !errors.Is(e, os.ErrNotExist) {
		return errors.New("unsafe publication sequence")
	}
	// Validate every artifact before changing public output. No partial-platform
	// release mode exists. Each build must record its version and trusted root.
	for _, target := range platforms {
		if err = validateArtifact(p, target, rootBytes); err != nil {
			return err
		}
	}
	keys := map[string]crypto.Signer{}
	for _, role := range []string{"targets", "snapshot", "timestamp"} {
		key, err := loadPrivate(p.Keys, role)
		if err != nil {
			return err
		}
		public, err := metadata.KeyFromPublicKey(key.Public())
		if err != nil {
			return err
		}
		id, err := public.ID()
		if err != nil {
			return err
		}
		ids := root.Signed.Roles[role]
		if ids == nil || ids.Threshold != 1 || len(ids.KeyIDs) != 1 || ids.KeyIDs[0] != id {
			return errors.New("signing key does not match publisher root role: " + role)
		}
		keys[role] = key
	}
	targetKey, snapshotKey, timestampKey := keys["targets"], keys["snapshot"], keys["timestamp"]
	extras := map[string][]byte{}
	for _, entry := range []struct{ name, path string }{{"start.sh", p.ClientScript}, {"server-install.sh", p.ServerScript}, {"latch-server.service", p.ServerUnit}, {"LICENSE", p.License}, {"root.json", filepath.Join(p.Keys, "root.json")}, {"publisher.pub", filepath.Join(p.Keys, "publisher.pub")}} {
		data, err := readRegular(entry.path, 65536, false)
		if err != nil {
			return err
		}
		extras[entry.name] = data
	}
	if len(extras["latch-server.service"]) > 16384 {
		return errors.New("server service unit exceeds bootstrap limit")
	}
	// Ensure the detached bootstrap key is the same authority as TUF targets.
	probe, err := signFile(targetKey, []byte("Latch publisher key check"))
	if err != nil || !verifyFile(extras["publisher.pub"], []byte("Latch publisher key check"), probe) {
		return errors.New("publisher public key does not match the targets signing key")
	}
	// Reserve the sequence before public writes. A failed publication may skip
	// a version, but must never reuse signed metadata versions after a crash.
	if err = atomicMode(counterPath, []byte(fmt.Sprint(version)+"\n"), 0600); err != nil {
		return err
	}
	for _, dir := range []string{p.Output, filepath.Join(p.Output, "updates"), filepath.Join(p.Output, "updates", "metadata"), filepath.Join(p.Output, "updates", "targets")} {
		if err = ensurePublicDir(dir); err != nil {
			return err
		}
	}
	files := map[string]string{}
	targets := metadata.Targets(p.Expires)
	targets.Signed.Version = version
	for _, target := range platforms {
		data, err := readRegular(filepath.Join(p.Artifacts, target.Name), 64<<20, false)
		if err != nil {
			return err
		}
		if err = validateImage(p, target, rootBytes, data); err != nil {
			return err
		}
		info, err := metadata.TargetFile().FromBytes(target.Name, data, "sha256")
		if err != nil {
			return err
		}
		custom, err := json.Marshal(map[string]any{"version": p.Version, "os": target.OS, "arch": target.Arch, "protocol": 1})
		if err != nil {
			return err
		}
		raw := json.RawMessage(custom)
		info.Custom = &raw
		targets.Signed.Targets[target.Name] = info
		sum := sha256.Sum256(data)
		files[target.Name] = fmt.Sprintf("%x", sum)
		receipt, err := readRegular(filepath.Join(p.Artifacts, target.Name+".build.json"), 4096, false)
		if err != nil {
			return err
		}
		extras[target.Name+".build.json"] = receipt
		if err = atomicFile(filepath.Join(p.Output, target.Name), data); err != nil {
			return err
		}
		if err = atomicFile(filepath.Join(p.Output, "updates", "targets", fmt.Sprintf("%x.%s", sum, target.Name)), data); err != nil {
			return err
		}
	}
	if err = signMetadata(targets, targetKey); err != nil {
		return err
	}
	if err = root.VerifyDelegate("targets", targets); err != nil {
		return err
	}
	targetBytes, err := targets.ToBytes(false)
	if err != nil {
		return err
	}
	snapshot := metadata.Snapshot(p.Expires)
	snapshot.Signed.Version = version
	snapshot.Signed.Meta["targets.json"] = reference(version, targetBytes)
	if err = signMetadata(snapshot, snapshotKey); err != nil {
		return err
	}
	if err = root.VerifyDelegate("snapshot", snapshot); err != nil {
		return err
	}
	snapshotBytes, err := snapshot.ToBytes(false)
	if err != nil {
		return err
	}
	timestampExpiry := now.Add(24 * time.Hour)
	if p.Expires.Before(timestampExpiry) {
		timestampExpiry = p.Expires
	}
	timestamp := metadata.Timestamp(timestampExpiry)
	timestamp.Signed.Version = version
	timestamp.Signed.Meta["snapshot.json"] = reference(version, snapshotBytes)
	if err = signMetadata(timestamp, timestampKey); err != nil {
		return err
	}
	if err = root.VerifyDelegate("timestamp", timestamp); err != nil {
		return err
	}
	timestampBytes, err := timestamp.ToBytes(false)
	if err != nil {
		return err
	}
	for _, entry := range []struct {
		name string
		data []byte
	}{
		{fmt.Sprintf("%d.root.json", root.Signed.Version), rootBytes},
		{fmt.Sprintf("%d.targets.json", version), targetBytes},
		{fmt.Sprintf("%d.snapshot.json", version), snapshotBytes},
		{"timestamp.json", timestampBytes},
	} {
		if err = atomicFile(filepath.Join(p.Output, "updates", "metadata", entry.name), entry.data); err != nil {
			return err
		}
	}
	for name, data := range extras {
		sum := sha256.Sum256(data)
		files[name] = fmt.Sprintf("%x", sum)
		if err = atomicFile(filepath.Join(p.Output, name), data); err != nil {
			return err
		}
		if strings.HasSuffix(name, ".sh") {
			sig, err := signFile(targetKey, data)
			if err != nil {
				return err
			}
			if err = atomicFile(filepath.Join(p.Output, name+".sig"), sig); err != nil {
				return err
			}
		}
	}
	var manifest strings.Builder
	fmt.Fprintf(&manifest, "Latch-Release 1\nVersion %s\nExpires %d\nSource %s\n", p.Version, p.Expires.Unix(), p.Commit)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(&manifest, "SHA256 %s %s\n", files[name], name)
	}
	data := []byte(manifest.String())
	sig, err := signFile(targetKey, data)
	if err != nil {
		return err
	}
	if err = atomicFile(filepath.Join(p.Output, "manifest.txt"), data); err != nil {
		return err
	}
	if err = atomicFile(filepath.Join(p.Output, "manifest.sig"), sig); err != nil {
		return err
	}
	return nil
}
func validateArtifact(p publication, target artifact, root []byte) error {
	data, err := readRegular(filepath.Join(p.Artifacts, target.Name), 64<<20, false)
	if err != nil {
		return err
	}
	return validateImage(p, target, root, data)
}
func validateImage(p publication, target artifact, root, data []byte) error {
	if err := validateBuildInfo(target, data); err != nil {
		return err
	}
	receiptBytes, err := readRegular(filepath.Join(p.Artifacts, target.Name+".build.json"), 4096, false)
	if err != nil {
		return err
	}
	var r buildReceipt
	if err = decodeObject(receiptBytes, &r); err != nil {
		return errors.New("invalid native build receipt: " + target.Name)
	}
	sum := sha256.Sum256(data)
	if r.Target != target.Name || r.SHA256 != fmt.Sprintf("%x", sum) || r.SourceCommit != p.Commit || r.Binary != expectedVersion(p.Version, target, root) {
		return errors.New("native build receipt does not match artifact, source, version or trust root: " + target.Name)
	}
	return nil
}
func validateBuildInfo(target artifact, data []byte) error {
	info, err := buildinfo.Read(bytes.NewReader(data))
	if err != nil || info.Path != target.Module || info.GoVersion != "go1.27.4" {
		return errors.New("wrong executable package or toolchain: " + target.Name)
	}
	settings := map[string]string{}
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	if settings["GOOS"] != target.OS || settings["GOARCH"] != target.Arch || settings["-trimpath"] != "true" {
		return errors.New("wrong executable platform or missing path trimming: " + target.Name)
	}
	return nil
}
