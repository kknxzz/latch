//go:build linux

package tests

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/pquerna/otp/hotp"
	"latch.local/server/internal/auth"
	"latch.local/server/internal/protocol"
)

// Opt-in only: this test installs a real service into a fresh disposable Linux
// VM. It refuses existing Latch files/accounts and never runs in normal tests.
func TestSystemdInstallerLifecycle(t *testing.T) {
	if os.Getenv("LATCH_INSTALLER_VM_TEST") != "1" {
		t.Skip("requires explicit disposable-VM opt-in")
	}
	if os.Geteuid() != 0 {
		t.Fatal("disposable-VM installation test requires root")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		t.Fatal("systemd is not running")
	}
	for _, path := range []string{"/etc/latch", "/var/lib/latch", "/usr/local/bin/latch-server", "/usr/local/lib/latch", "/usr/local/share/doc/latch", "/etc/systemd/system/latch-server.service"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("refusing an existing Latch installation path: %s", path)
		}
	}
	if exec.Command("getent", "passwd", "latch").Run() == nil || exec.Command("getent", "group", "latch").Run() == nil {
		t.Fatal("refusing an existing latch account/group")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	command := func(program string, args ...string) []byte {
		t.Helper()
		cmd := exec.CommandContext(ctx, program, args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s failed: %v: %s", program, err, output)
		}
		return output
	}
	command("useradd", "--system", "--user-group", "--home-dir", "/var/lib/latch", "--no-create-home", "--shell", "/usr/sbin/nologin", "latch")
	uid, err := strconv.Atoi(strings.TrimSpace(string(command("id", "-u", "latch"))))
	if err != nil {
		t.Fatal(err)
	}
	gid, err := strconv.Atoi(strings.TrimSpace(string(command("id", "-g", "latch"))))
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll("/etc/latch/tls", 0700); err != nil {
		t.Fatal(err)
	}
	cert, key, leaf := productionCertificate(t, "/etc/latch/tls")
	for _, path := range []string{"/etc/latch/tls", cert, key} {
		if err = os.Chown(path, uid, gid); err != nil {
			t.Fatal(err)
		}
	}
	script, err := filepath.Abs("../scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = exec.CommandContext(cleanup, "sh", script, "uninstall").Run()
	})
	build := func(version string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "latch-server")
		cmd := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags", "-buildid= -s -w -X main.version="+version, "-o", path, "./cmd/latch-server")
		cmd.Dir = ".."
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("native server build: %v: %s", err, output)
		}
		return path
	}
	binary := build("0.1.0")
	parent, err := os.Stat(filepath.Dir(binary))
	if err != nil || parent.Mode().Perm() != 0700 {
		t.Fatal("candidate fixture must remain in a root-only directory")
	}
	var entropy [32]byte
	if _, err = rand.Read(entropy[:]); err != nil {
		t.Fatal(err)
	}
	password := base64.RawURLEncoding.EncodeToString(entropy[:])
	clear(entropy[:])
	var secretBytes [20]byte
	if _, err = rand.Read(secretBytes[:]); err != nil {
		t.Fatal(err)
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secretBytes[:])
	clear(secretBytes[:])
	confirmation, err := hotp.GenerateCode(secret, uint64(time.Now().Unix()/30))
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := json.Marshal(map[string]string{"password": password, "totp_secret": secret, "confirmation": confirmation})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(credentials)
	input := filepath.Join(t.TempDir(), "credentials.json")
	if err = os.WriteFile(input, credentials, 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(input)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	address := func() string {
		t.Helper()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		result := listener.Addr().String()
		listener.Close()
		return result
	}
	publicAddress, adminAddress := address(), address()
	_, publicPort, _ := net.SplitHostPort(publicAddress)
	_, adminPort, _ := net.SplitHostPort(adminAddress)
	publicOrigin, adminOrigin := "https://chat.example:"+publicPort, "https://admin.example:"+adminPort
	install := exec.CommandContext(ctx, "sh", script, "install", "--binary", binary, "--", "--non-interactive", "--tls", "files", "--public-url", publicOrigin, "--admin-url", adminOrigin, "--listen", publicAddress, "--admin-listen", adminAddress, "--cert", cert, "--key", key, "--admin-cert", cert, "--admin-key", key, "--credentials-fd", "3")
	install.ExtraFiles = []*os.File{file}
	if output, err := install.CombinedOutput(); err != nil {
		t.Fatalf("fresh installation failed: %v: %s", err, output)
	}
	for _, path := range []string{"/etc/latch/server.json", "/var/lib/latch/state.db"} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 || info.Sys().(*syscall.Stat_t).Uid != uint32(uid) {
			t.Fatal("unsafe installed security-state ownership/mode", path, err)
		}
	}
	configuration, err := os.ReadFile("/etc/latch/server.json")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	client := func(host, address string) *http.Client {
		transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: host, MinVersion: tls.VersionTLS13}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, address)
		}}
		t.Cleanup(transport.CloseIdleConnections)
		jar, _ := cookiejar.New(nil)
		return &http.Client{Transport: transport, Jar: jar, Timeout: 3 * time.Second}
	}
	publicClient, privateClient := client("chat.example", publicAddress), client("admin.example", adminAddress)
	request := func(c *http.Client, origin, method, path string, body any, csrf string, status int) []byte {
		t.Helper()
		var data []byte
		if body != nil {
			data, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(data)
		}
		r, err := http.NewRequestWithContext(ctx, method, origin+path, bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", origin)
		}
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		response, err := c.Do(r)
		if err != nil {
			t.Fatal("installed TLS request failed", err)
		}
		defer response.Body.Close()
		payload, err := io.ReadAll(io.LimitReader(response.Body, 65536))
		if err != nil || response.StatusCode != status {
			t.Fatalf("unexpected %s response: %d (wanted %d): %v", path, response.StatusCode, status, err)
		}
		return payload
	}
	info := func() string {
		t.Helper()
		var result struct {
			ServerID string `json:"server_id"`
		}
		if err := json.Unmarshal(request(publicClient, publicOrigin, "GET", "/v1/info", nil, "", 200), &result); err != nil || !auth.ValidUUID(result.ServerID) {
			t.Fatal("invalid installed server identity", err)
		}
		return result.ServerID
	}
	serverID := info()
	request(privateClient, adminOrigin, "GET", "/admin/api/devices", nil, "", 401)
	var challenge auth.Challenge
	if err = json.Unmarshal(request(publicClient, publicOrigin, "POST", "/v1/enroll/challenge", struct{}{}, "", 200), &challenge); err != nil {
		t.Fatal(err)
	}
	code := command("/usr/local/bin/latch-server", "enrollment-code", "--state-dir", "/var/lib/latch")
	defer clear(code)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(priv)
	deviceID := auth.NewUUID()
	enrollment := auth.Enrollment{ChallengeID: challenge.ID, Code: strings.TrimSpace(string(code)), UUID: deviceID, PublicKey: pub, Nickname: "Installer Fixture"}
	enrollment.Signature = ed25519.Sign(priv, protocol.Transcript([]byte("Latch/enroll/v1"), []byte(challenge.ServerID), []byte(challenge.ID), challenge.Nonce, []byte(deviceID), pub))
	request(publicClient, publicOrigin, "POST", "/v1/enroll", enrollment, "", 201)
	loginCode, err := hotp.GenerateCode(secret, uint64(time.Now().Unix()/30)+1)
	if err != nil {
		t.Fatal(err)
	}
	var login struct {
		CSRF string `json:"csrf"`
	}
	if err = json.Unmarshal(request(privateClient, adminOrigin, "POST", "/admin/api/login", map[string]string{"password": password, "totp": loginCode}, "", 200), &login); err != nil || login.CSRF == "" {
		t.Fatal("installed private administration login failed", err)
	}
	request(privateClient, adminOrigin, "POST", "/admin/api/devices/"+deviceID+"/ban", struct{}{}, login.CSRF, 200)
	command("sh", script, "install", "--binary", binary) // Idempotent installation.
	if info() != serverID {
		t.Fatal("reinstallation replaced the network identity")
	}
	command("sh", script, "upgrade", "--binary", build("0.1.1"))
	if strings.TrimSpace(string(command("/usr/local/bin/latch-server", "version"))) != "Latch Server 0.1.1" || info() != serverID {
		t.Fatal("upgrade did not preserve identity and replace the executable")
	}
	if output, err := exec.CommandContext(ctx, "sh", script, "upgrade", "--binary", binary).CombinedOutput(); err == nil || !strings.Contains(string(output), "downgrade") {
		t.Fatalf("an older release was not rejected: %v: %s", err, output)
	}
	if info() != serverID {
		t.Fatal("rejected downgrade disturbed the running network")
	}
	bad := filepath.Join(t.TempDir(), "failing-server")
	if err = os.WriteFile(bad, []byte("#!/bin/sh\ncase \"$1\" in\n version) echo 'Latch Server 0.1.2';;\n doctor) exit 0;;\n *) exit 42;;\nesac\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.CommandContext(ctx, "sh", script, "upgrade", "--binary", bad).CombinedOutput(); err == nil || !strings.Contains(string(output), "restored the previous binary") {
		t.Fatalf("startup failure did not trigger rollback: %v: %s", err, output)
	}
	if strings.TrimSpace(string(command("/usr/local/bin/latch-server", "version"))) != "Latch Server 0.1.1" || info() != serverID {
		t.Fatal("rollback failed to restore the running gateway")
	}
	current, err := os.ReadFile("/etc/latch/server.json")
	if err != nil || !bytes.Equal(configuration, current) {
		t.Fatal("installation/upgrade changed existing configuration")
	}
	command("sh", script, "uninstall")
	for _, path := range []string{"/usr/local/bin/latch-server", "/etc/systemd/system/latch-server.service"} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("uninstall left managed executable/unit", path)
		}
	}
	if exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", "latch-server.service").Run() == nil {
		t.Fatal("uninstalled service remains active")
	}
	command("getent", "passwd", "latch")
	store, err := auth.Open("/var/lib/latch/state.db", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	devices, err := store.Devices()
	if err != nil || store.ServerID() != serverID || len(devices) != 1 || devices[0].UUID != deviceID || !devices[0].Banned {
		t.Fatal("uninstall lost security state or a permanent ban", err)
	}
}
