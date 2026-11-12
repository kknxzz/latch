// Package update verifies explicit software updates with TUF. It has no timer,
// background worker, enrollment credentials or conversation-state access.
package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"debug/buildinfo"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	tufconfig "github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
	"latch.local/client/internal/protocol"
)

const maxBinary = 64 << 20

// Release builders supply a genuinely provisioned public root using -X. An
// ordinary development build has no publisher authority and fails closed.
var rootBase64 string

func EmbeddedRoot() ([]byte, error) {
	data, err := base64.StdEncoding.Strict().DecodeString(rootBase64)
	if err != nil || len(data) == 0 || len(data) > 65536 {
		return nil, errors.New("this build has no configured release trust root")
	}
	return data, nil
}

type Options struct {
	RepositoryURL, StateDir, Executable, CurrentVersion string
	Root                                                []byte
	CheckOnly                                           bool
	// HTTPClient is for embedders with a protected transport policy, such as a
	// private CA. The CLI exposes no certificate-verification bypass.
	HTTPClient *http.Client
}
type Result struct {
	Version            string
	Installed, Current bool
}
type targetDescription struct {
	Version  string `json:"version"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Protocol int    `json:"protocol"`
}

func TargetName() string { return "latch-" + runtime.GOOS + "-" + runtime.GOARCH }

// Run verifies metadata before downloading an artifact, and verifies its length,
// hashes and platform before atomically replacing the current executable.
func Run(ctx context.Context, options Options) (result Result, err error) {
	base, err := repositoryURL(options.RepositoryURL)
	if err != nil {
		return result, err
	}
	if len(options.Root) == 0 || len(options.Root) > 65536 {
		return result, errors.New("a pinned release trust root is required")
	}
	if _, err = metadata.Root().FromBytes(options.Root); err != nil {
		return result, errors.New("invalid release trust root")
	}
	if _, _, err = releaseVersion(options.CurrentVersion, true); err != nil {
		return result, err
	}
	if !filepath.IsAbs(options.StateDir) {
		return result, errors.New("update state requires an absolute private directory")
	}
	if options.Executable == "" {
		options.Executable, err = os.Executable()
		if err != nil {
			return result, err
		}
	}
	executable, err := filepath.EvalSymlinks(options.Executable)
	if err != nil {
		return result, err
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return result, err
	}
	unlock, err := lockExecutable(executable)
	if err != nil {
		return result, err
	}
	defer unlock()
	if err = privateDirectory(options.StateDir); err != nil {
		return result, err
	}
	anchor := sha256.Sum256(options.Root)
	cache := filepath.Join(options.StateDir, hex.EncodeToString(anchor[:]))
	if err = privateDirectory(cache); err != nil {
		return result, err
	}
	if err = validateCache(cache); err != nil {
		return result, err
	}
	// This cache is an owner-only trust store. Keep the newest previously trusted
	// root so root rotation cannot be silently reset to an older embedded root.
	trusted := options.Root
	if cached, e := os.ReadFile(filepath.Join(cache, "root.json")); e == nil {
		trusted = cached
	} else if !errors.Is(e, os.ErrNotExist) {
		return result, e
	}
	cfg, err := tufconfig.New(base+"/metadata", trusted)
	if err != nil {
		return result, err
	}
	cfg.LocalMetadataDir, cfg.LocalTargetsDir = cache, cache
	cfg.RemoteTargetsURL = base + "/targets"
	cfg.RootMaxLength, cfg.TimestampMaxLength = 65536, 16384
	cfg.SnapshotMaxLength, cfg.TargetsMaxLength = 65536, 131072
	cfg.MaxRootRotations, cfg.MaxDelegations = 32, 4
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	client := options.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16384, IdleConnTimeout: 30 * time.Second, MaxIdleConns: 2, MaxConnsPerHost: 2}}
	}
	copyClient := *client
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	defer copyClient.CloseIdleConnections()
	transportFetcher := fetcher.NewDefaultFetcher()
	transportFetcher.SetHTTPClient(&boundedClient{ctx: ctx, client: &copyClient})
	cfg.Fetcher = transportFetcher
	up, err := updater.New(cfg)
	if err != nil {
		return result, err
	}
	// Persist high-water marks even when a later download fails. TUF writes
	// atomically; sync those files and the directory before returning.
	defer func() { err = errors.Join(err, syncCache(cache)) }()
	if err = up.Refresh(); err != nil {
		return result, fmt.Errorf("release metadata verification failed: %w", err)
	}
	target, err := up.GetTargetInfo(TargetName())
	if err != nil {
		return result, err
	}
	if target.Path != TargetName() || target.Length < 1 || target.Length > maxBinary || len(target.Hashes["sha256"]) != 32 || target.Custom == nil {
		return result, errors.New("invalid release target")
	}
	var description targetDescription
	if protocol.Strict(*target.Custom, &description) != nil || description.OS != runtime.GOOS || description.Arch != runtime.GOARCH || description.Protocol != 1 {
		return result, errors.New("incompatible release target")
	}
	comparison, err := compareVersion(description.Version, options.CurrentVersion)
	if err != nil {
		return result, err
	}
	result.Version = description.Version
	if comparison < 0 {
		return result, errors.New("release would downgrade the installed client")
	}
	if comparison == 0 {
		result.Current = true
		return result, nil
	}
	if options.CheckOnly {
		return result, nil
	}
	stage, err := os.CreateTemp(filepath.Dir(executable), ".latch-update-")
	if err != nil {
		return result, errors.New("cannot stage update; install Latch in a directory you own")
	}
	defer os.Remove(stage.Name())
	defer stage.Close()
	if err = stage.Close(); err != nil {
		return result, err
	}
	_, data, err := up.DownloadTarget(target, stage.Name(), "")
	if err != nil {
		return result, err
	}
	info, err := buildinfo.Read(bytes.NewReader(data))
	if err != nil || info.Path != "latch.local/client/cmd/latch" {
		return result, errors.New("release is not a Latch client executable")
	}
	settings := map[string]string{}
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	if settings["GOOS"] != runtime.GOOS || settings["GOARCH"] != runtime.GOARCH {
		return result, errors.New("release executable has the wrong platform")
	}
	if err = verifyExecutableVersion(ctx, stage.Name(), description.Version); err != nil {
		return result, err
	}
	result.Installed, err = installStage(stage.Name(), executable)
	if err != nil {
		return result, err
	}
	return result, nil
}

type versionOutput struct{ bytes.Buffer }

func (out *versionOutput) Write(data []byte) (int, error) {
	if out.Len()+len(data) > 256 {
		return 0, errors.New("release version output limit exceeded")
	}
	return out.Buffer.Write(data)
}
func verifyExecutableVersion(ctx context.Context, path, version string) error {
	// Execute only after TUF authentication, content-hash verification and
	// platform validation, and reject accidental publisher version mismatches.
	if err := os.Chmod(path, 0700); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "version")
	var out versionOutput
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("verified release could not report its version")
	}
	if strings.TrimSpace(out.String()) != "Latch "+version {
		return errors.New("executable version does not match signed release metadata")
	}
	return nil
}

type boundedClient struct {
	ctx      context.Context
	client   *http.Client
	requests atomic.Int32
}

func (c *boundedClient) Do(request *http.Request) (*http.Response, error) {
	if c.requests.Add(1) > 64 {
		return nil, errors.New("update request limit exceeded")
	}
	return c.client.Do(request.Clone(c.ctx))
}
func repositoryURL(raw string) (string, error) {
	if len(raw) > 2048 {
		return "", errors.New("release repository URL is too long")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || u.Opaque != "" || strings.Contains(u.Path, "..") || strings.ContainsAny(raw, "\\ \t\r\n") {
		return "", errors.New("release repository requires an HTTPS URL without credentials or query parameters")
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String(), nil
}
func releaseVersion(raw string, development bool) ([3]uint64, bool, error) {
	var result [3]uint64
	if len(raw) > 40 {
		return result, false, errors.New("invalid release version")
	}
	dev := development && strings.HasSuffix(raw, "-dev")
	if dev {
		raw = strings.TrimSuffix(raw, "-dev")
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || len(raw) > 40 {
		return result, false, errors.New("invalid release version")
	}
	for i, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return result, false, errors.New("invalid release version")
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return result, false, errors.New("invalid release version")
			}
		}
		value, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return result, false, errors.New("invalid release version")
		}
		result[i] = value
	}
	return result, dev, nil
}
func compareVersion(target, current string) (int, error) {
	a, _, err := releaseVersion(target, false)
	if err != nil {
		return 0, err
	}
	b, dev, err := releaseVersion(current, true)
	if err != nil {
		return 0, err
	}
	for i := range a {
		if a[i] > b[i] {
			return 1, nil
		}
		if a[i] < b[i] {
			return -1, nil
		}
	}
	if dev {
		return 1, nil
	}
	return 0, nil
}
