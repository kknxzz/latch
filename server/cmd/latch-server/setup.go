package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"latch.local/server/internal/admin"
	"latch.local/server/internal/auth"
	"latch.local/server/internal/config"
)

func runSetup(args []string) error {
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	path := flags.String("config", "/etc/latch/server.json", "New protected configuration file")
	state := flags.String("state-dir", "/var/lib/latch", "Private state directory")
	publicURL := flags.String("public-url", "", "Public HTTPS origin")
	adminURL := flags.String("admin-url", "", "Separate private dashboard HTTPS origin")
	mode := flags.String("tls", "acme", "acme, files or proxy")
	listen := flags.String("listen", "", "Public bind address (default :443, or loopback :8080 for proxy)")
	private := flags.String("admin-listen", "127.0.0.1:8443", "Private administrative bind address")
	httpListen := flags.String("acme-http-listen", "0.0.0.0:80", "HTTP-01 challenge bind address")
	terms := flags.Bool("accept-acme-terms", false, "Accept the ACME certificate authority terms")
	cert := flags.String("cert", "", "Public PEM certificate")
	key := flags.String("key", "", "Public PEM private key, mode 0600")
	adminCert := flags.String("admin-cert", "", "Administrative PEM certificate")
	adminKey := flags.String("admin-key", "", "Administrative PEM private key, mode 0600")
	proxies := flags.String("trusted-proxies", "", "Comma-separated explicitly trusted proxy CIDRs")
	noninteractive := flags.Bool("non-interactive", false, "Require all input through flags and a private credentials file descriptor")
	fd := flags.Int("credentials-fd", -1, "Administrator credentials file descriptor, >=3")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !filepath.IsAbs(*path) || !filepath.IsAbs(*state) || len(filepath.Join(*state, "admin.sock")) > 100 || (*fd != -1 && *fd < 3) {
		return errors.New("invalid setup arguments; use absolute configuration and short state paths")
	}
	if *mode != "acme" && *mode != "files" && *mode != "proxy" {
		return errors.New("TLS mode must be acme, files or proxy")
	}
	if (*mode == "acme" && (*cert != "" || *key != "" || *adminCert != "" || *adminKey != "")) || (*mode == "proxy" && (*cert != "" || *key != "")) {
		return errors.New("certificate arguments conflict with selected TLS mode")
	}
	if _, err := os.Lstat(*path); err == nil {
		if _, err = config.Load(*path); err != nil {
			return err
		}
		fmt.Println("Configuration already exists. Setup leaves it unchanged; use admin reset for credential recovery.")
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var tty *os.File
	prompt := func(label string, value *string) error {
		if *value != "" {
			return nil
		}
		if *noninteractive {
			return errors.New(label + " is required")
		}
		if tty == nil {
			var err error
			tty, err = os.OpenFile("/dev/tty", os.O_RDWR, 0)
			if err != nil {
				return errors.New("setup requires a terminal or --non-interactive input")
			}
		}
		answer, err := admin.ReadLine(ctx, tty, label+": ")
		if err != nil {
			return err
		}
		*value = strings.TrimSpace(answer)
		if *value == "" {
			return errors.New(label + " is required")
		}
		return nil
	}
	defer func() {
		if tty != nil {
			tty.Close()
		}
	}()
	if err := prompt("Server URL (https://chat.example)", publicURL); err != nil {
		return err
	}
	if err := prompt("Private dashboard URL (https://admin.example:8443)", adminURL); err != nil {
		return err
	}
	if *mode == "acme" && !*terms {
		if *noninteractive {
			return errors.New("automatic TLS requires explicit --accept-acme-terms")
		}
		answer := ""
		if err := prompt("Read https://letsencrypt.org/repository/ and accept its subscriber terms? Type yes", &answer); err != nil {
			return err
		}
		if answer != "yes" {
			return errors.New("ACME terms were not accepted; use certificate files instead")
		}
		*terms = true
	}
	c := config.Config{StateDir: *state, PublicURL: *publicURL, AdminURL: *adminURL, TLSMode: *mode, PublicListen: *listen, AdminListen: *private, MaxConnections: 100, MaxRooms: 20, MaxMembers: 16}
	if *proxies != "" {
		for _, prefix := range strings.Split(*proxies, ",") {
			c.TrustedProxies = append(c.TrustedProxies, strings.TrimSpace(prefix))
		}
	}
	if c.PublicListen == "" {
		c.PublicListen = "0.0.0.0:443"
		if *mode == "proxy" {
			c.PublicListen = "127.0.0.1:8080"
		}
	}
	if *mode == "acme" {
		c.ACMEHTTPListen, c.ACMEAcceptTerms = *httpListen, *terms
	} else {
		if err := prompt("Administrative certificate path", adminCert); err != nil {
			return err
		}
		if err := prompt("Administrative private key path", adminKey); err != nil {
			return err
		}
		c.AdminCertFile, c.AdminKeyFile = *adminCert, *adminKey
		if *mode == "files" {
			if err := prompt("Public certificate path", cert); err != nil {
				return err
			}
			if err := prompt("Public private key path", key); err != nil {
				return err
			}
			c.CertFile, c.KeyFile = *cert, *key
		} else if *mode == "proxy" {
			if err := prompt("Trusted proxy CIDRs", proxies); err != nil {
				return err
			}
			if len(c.TrustedProxies) == 0 {
				for _, prefix := range strings.Split(*proxies, ",") {
					c.TrustedProxies = append(c.TrustedProxies, strings.TrimSpace(prefix))
				}
			}
		}
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if err := config.PrivateDir(c.StateDir); err != nil {
		return err
	}
	if _, err := config.PrepareTLS(c); err != nil {
		return err
	}
	store, err := auth.Open(filepath.Join(c.StateDir, "state.db"), nil)
	if err != nil {
		return err
	}
	_, credentialErr := store.AdminCredentials()
	_ = store.Close()
	if errors.Is(credentialErr, auth.ErrAdminUninitialized) {
		if *noninteractive && *fd < 3 {
			return errors.New("non-interactive setup requires --credentials-fd for initial administration")
		}
		adminArgs := []string{"init", "--state-dir", c.StateDir}
		if *fd >= 3 {
			adminArgs = append(adminArgs, "--credentials-fd", strconv.Itoa(*fd))
		}
		if err = runAdmin(adminArgs); err != nil {
			return err
		}
	} else if credentialErr != nil {
		return credentialErr
	}
	if err = config.SaveNew(*path, c); err != nil {
		return err
	}
	fmt.Println("Configuration saved:", *path)
	fmt.Println("Dashboard:", strings.TrimSuffix(c.AdminURL, "/")+"/admin/")
	if *mode == "acme" {
		fmt.Println("Both hostnames must reach this VM on public port 80 for certificate validation. Only ACME challenges are served there.")
	}
	fmt.Println("Access the dashboard through WireGuard or an SSH forward. Keep its listener private.")
	fmt.Println("Run latch-server doctor --config", *path, "as the service account before starting the service.")
	return nil
}

func runDoctor(args []string) error {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	path := flags.String("config", "/etc/latch/server.json", "Protected configuration file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected doctor arguments")
	}
	c, err := config.Load(*path)
	if err != nil {
		return err
	}
	if len(filepath.Join(c.StateDir, "admin.sock")) > 100 {
		return errors.New("state path is too long for local administration")
	}
	if _, err = config.PrepareTLS(c); err != nil {
		return err
	}
	info, localErr := admin.CallLocal(context.Background(), c.StateDir, "server.info")
	if localErr == nil {
		if !info.AdminInitialized {
			return errors.New("administrator is not initialized")
		}
	} else {
		if _, err = os.Lstat(filepath.Join(c.StateDir, "state.db")); err != nil {
			return errors.New("server state is missing; run setup first")
		}
		store, err := auth.Open(filepath.Join(c.StateDir, "state.db"), nil)
		if err != nil {
			return errors.New("state inaccessible; run doctor as the service account")
		}
		_, credentialErr := store.AdminCredentials()
		_ = store.Close()
		if credentialErr != nil {
			return credentialErr
		}
	}
	fmt.Println("Local configuration, TLS material and administrator state are valid.")
	fmt.Println("No DNS, certificate issuance, remote reachability or firewall checks were performed.")
	return nil
}
