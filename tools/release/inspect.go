package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

type binaryVersion struct {
	Version    string `json:"version"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	Protocol   int    `json:"protocol"`
	RootSHA256 string `json:"root_sha256"`
}
type buildReceipt struct {
	Target       string        `json:"target"`
	SHA256       string        `json:"sha256"`
	SourceCommit string        `json:"source_commit"`
	Binary       binaryVersion `json:"binary"`
}

func expectedVersion(version string, target artifact, root []byte) binaryVersion {
	r := binaryVersion{Version: version, OS: target.OS, Arch: target.Arch, Protocol: 1}
	if target.Module == "latch.local/client/cmd/latch" {
		r.RootSHA256 = fmt.Sprintf("%x", sha256.Sum256(root))
	}
	return r
}
func decodeObject(data []byte, object any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(object); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

type limitedOutput struct{ bytes.Buffer }

func (w *limitedOutput) Write(p []byte) (int, error) {
	if w.Len()+len(p) > 4096 {
		return 0, errors.New("version output exceeded 4 KiB")
	}
	return w.Buffer.Write(p)
}

// inspect executes only an operator's own locally built executable. It is a
// build step, never an authenticity check for an unverified downloaded program.
// Receipts record native-runner evidence; they are not independent attestations.
func inspect(binary, targetName, rootPath, version, commit string) error {
	var target artifact
	for _, candidate := range platforms {
		if candidate.Name == targetName {
			target = candidate
		}
	}
	if target.Name == "" || target.OS != runtime.GOOS || target.Arch != runtime.GOARCH {
		return errors.New("inspect must run on the artifact's native platform")
	}
	if !validVersion(version) || len(commit) != 40 || strings.Trim(commit, "0123456789abcdef") != "" {
		return errors.New("invalid release version or source commit")
	}
	if !filepath.IsAbs(binary) {
		return errors.New("binary path must be absolute")
	}
	data, err := readRegular(binary, 64<<20, false)
	if err != nil {
		return err
	}
	if err = validateBuildInfo(target, data); err != nil {
		return err
	}
	root, err := readRegular(rootPath, 65536, false)
	if err != nil {
		return err
	}
	anchor, err := metadata.Root().FromBytes(root)
	if err != nil || anchor.VerifyDelegate("root", anchor) != nil || !anchor.Signed.Expires.After(time.Now()) {
		return errors.New("inspection requires a current self-verified publisher root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "version", "--json")
	var output limitedOutput
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	if err = cmd.Run(); err != nil {
		return errors.New("native version probe failed")
	}
	var v binaryVersion
	if err = decodeObject(output.Bytes(), &v); err != nil || v != expectedVersion(version, target, root) {
		return errors.New("native version, platform, protocol or trust root does not match release inputs")
	}
	// Fail if the build input was replaced while its version command ran.
	after, err := readRegular(binary, 64<<20, false)
	if err != nil || !bytes.Equal(data, after) {
		return errors.New("artifact changed during inspection")
	}
	sum := sha256.Sum256(data)
	receipt, err := json.MarshalIndent(buildReceipt{Target: target.Name, SHA256: fmt.Sprintf("%x", sum), SourceCommit: commit, Binary: v}, "", "  ")
	if err != nil {
		return err
	}
	return writeNew(binary+".build.json", append(receipt, '\n'), os.FileMode(0644))
}

func verifyArtifacts(dir, rootPath, version, commit string) error {
	if !filepath.IsAbs(dir) || !validVersion(version) || len(commit) != 40 || strings.Trim(commit, "0123456789abcdef") != "" {
		return errors.New("explicit artifacts, version and source commit are required")
	}
	root, err := readRegular(rootPath, 65536, false)
	if err != nil {
		return err
	}
	anchor, err := metadata.Root().FromBytes(root)
	if err != nil || anchor.VerifyDelegate("root", anchor) != nil || !anchor.Signed.Expires.After(time.Now()) {
		return errors.New("verification requires a current self-verified publisher root")
	}
	p := publication{Artifacts: dir, Version: version, Commit: commit}
	for _, target := range platforms {
		if err = validateArtifact(p, target, root); err != nil {
			return err
		}
	}
	return nil
}
