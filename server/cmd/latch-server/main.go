package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/netutil"
	"latch.local/server/internal/admin"
	"latch.local/server/internal/auth"
	"latch.local/server/internal/config"
	"latch.local/server/internal/gateway"
)

var version = "0.1.0-dev"

// net/http diagnostics can contain remote addresses and panic values. Retain
// only a fixed event in the bounded, private event ring.
type httpDiagnostics func()

func (record httpDiagnostics) Write(p []byte) (int, error) {
	record()
	return len(p), nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Latch:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) > 0 && args[0] == "setup" {
		return runSetup(args[1:])
	}
	if len(args) > 0 && args[0] == "doctor" {
		return runDoctor(args[1:])
	}
	if len(args) > 0 && args[0] == "admin" {
		return runAdmin(args[1:])
	}
	if len(args) == 1 && args[0] == "version" {
		fmt.Println("Latch Server", version)
		return nil
	}
	if len(args) == 2 && args[0] == "version" && args[1] == "--json" {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"version": version, "os": runtime.GOOS, "arch": runtime.GOARCH, "protocol": 1, "root_sha256": ""})
	}
	if len(args) > 0 && args[0] == "enrollment-code" {
		flags := flag.NewFlagSet("enrollment-code", flag.ContinueOnError)
		dir := flags.String("state-dir", "", "Private server state directory")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *dir == "" || flags.NArg() != 0 {
			return errors.New("enrollment-code requires --state-dir")
		}
		absolute, err := filepath.Abs(*dir)
		if err != nil {
			return err
		}
		response, err := admin.CallLocal(context.Background(), absolute, "enrollment.generate")
		if err != nil {
			return err
		}
		fmt.Println(response.Code)
		return nil
	}
	if len(args) == 0 || args[0] != "serve" {
		return errors.New("usage: latch-server serve --config FILE, or serve --dev --state-dir DIR")
	}
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "", "Protected server configuration")
	dev := flags.Bool("dev", false, "Explicit localhost development mode")
	stateDir := flags.String("state-dir", "", "Development state directory")
	listen := flags.String("listen", "127.0.0.1:8080", "Development listen address")
	adminListen := flags.String("admin-listen", "", "Development administrative listen address")
	enrollmentFile := flags.String("enrollment-file", "", "Development-only code output file; must not exist")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	var c config.Config
	var err error
	if *dev {
		if *configPath != "" || *stateDir == "" {
			return errors.New("development requires --state-dir and no --config")
		}
		dir, e := filepath.Abs(*stateDir)
		if e != nil {
			return e
		}
		c = config.Development(dir)
		c.PublicListen = *listen
		if *adminListen != "" {
			c.AdminListen = *adminListen
		}
	} else {
		if *configPath == "" || *stateDir != "" || *enrollmentFile != "" || *adminListen != "" {
			return errors.New("production requires --config")
		}
		c, err = config.Load(*configPath)
		if err != nil {
			return err
		}
	}
	if err = c.Validate(); err != nil {
		return err
	}
	store, err := auth.Open(filepath.Join(c.StateDir, "state.db"), nil)
	if err != nil {
		return err
	}
	defer store.Close()
	if !c.Development {
		if _, err = store.AdminCredentials(); err != nil {
			return errors.New("initialize administrator credentials locally before production startup")
		}
	}
	material, err := config.PrepareTLS(c)
	if err != nil {
		return err
	}
	local, err := admin.ListenLocal(store, c.StateDir)
	if err != nil {
		return err
	}
	defer local.Close()
	if *enrollmentFile != "" {
		if !c.Development {
			return errors.New("enrollment output is development-only")
		}
		code, _, e := store.GenerateCode()
		if e != nil {
			return e
		}
		file, e := os.OpenFile(*enrollmentFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return errors.New("could not create enrollment output file")
		}
		_, e = file.WriteString(code + "\n")
		closeErr := file.Close()
		if e != nil {
			return e
		}
		if closeErr != nil {
			return closeErr
		}
	}
	proxies, err := c.ProxyPrefixes()
	if err != nil {
		return err
	}
	var dashboard *admin.Handler
	g, err := gateway.New(store, gateway.Options{Limits: c.Limits(), TrustedProxies: proxies, SecurityEvent: func(kind, deviceID string) {
		if dashboard != nil {
			dashboard.Record(kind, deviceID)
		}
	}})
	if err != nil {
		return err
	}
	defer g.Close()
	// Administration is intentionally not attached to the public listener.
	server := &http.Server{Addr: c.PublicListen, Handler: g, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384, TLSConfig: material.Public, ErrorLog: log.New(httpDiagnostics(func() {
		if dashboard != nil {
			dashboard.Record("gateway_http_error", "")
		}
	}), "", 0)}
	listener, err := net.Listen("tcp", c.PublicListen)
	if err != nil {
		return errors.New("could not bind public listener")
	}
	defer listener.Close()
	listener = netutil.LimitListener(listener, c.MaxConnections+32)
	privateListener, err := net.Listen("tcp", c.AdminListen)
	if err != nil {
		return errors.New("could not bind private administrative listener")
	}
	defer privateListener.Close()
	privateListener = netutil.LimitListener(privateListener, 16)
	origin := strings.TrimSuffix(c.AdminURL, "/")
	if c.Development {
		origin = "http://" + privateListener.Addr().String()
	}
	dashboard, err = admin.NewHandler(store, g, admin.HandlerOptions{Origin: origin, Development: c.Development})
	if err != nil {
		return err
	}
	privateServer := &http.Server{Handler: dashboard, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384, TLSConfig: material.Admin, ErrorLog: log.New(httpDiagnostics(func() { dashboard.Record("admin_http_error", "") }), "", 0)}
	defer privateServer.Close()
	defer server.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	served := make(chan error, 3)
	if material.Challenge != nil {
		challenge := &http.Server{Addr: c.ACMEHTTPListen, Handler: material.Challenge, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384, ErrorLog: log.New(httpDiagnostics(func() { dashboard.Record("acme_http_error", "") }), "", 0)}
		challengeListener, e := net.Listen("tcp", c.ACMEHTTPListen)
		if e != nil {
			return errors.New("could not bind ACME HTTP challenge listener")
		}
		defer challengeListener.Close()
		challengeListener = netutil.LimitListener(challengeListener, 32)
		defer challenge.Close()
		go func() { served <- challenge.Serve(challengeListener) }()
	}
	go func() {
		if material.Public != nil {
			served <- server.ServeTLS(listener, "", "")
		} else {
			served <- server.Serve(listener)
		}
	}()
	go func() {
		if c.Development {
			served <- privateServer.Serve(privateListener)
		} else {
			served <- privateServer.ServeTLS(privateListener, "", "")
		}
	}()
	fmt.Fprintln(os.Stderr, "Latch gateway listening on", listener.Addr())
	fmt.Fprintln(os.Stderr, "Latch administration listening on", privateListener.Addr())
	if err = notifyReady(); err != nil {
		return err
	}
	select {
	case err = <-served:
		if !errors.Is(err, http.ErrServerClosed) {
			return errors.New("HTTP service failed")
		}
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdown)
	_ = privateServer.Shutdown(shutdown)
	return g.Close()
}
