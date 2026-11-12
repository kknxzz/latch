package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

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
	if len(args) > 0 && args[0] == "admin" {
		return runAdmin(args[1:])
	}
	if len(args) == 1 && args[0] == "version" {
		fmt.Println("Latch Server", version)
		return nil
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
	server := &http.Server{Addr: c.PublicListen, Handler: g, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}, ErrorLog: log.New(httpDiagnostics(func() {
		if dashboard != nil {
			dashboard.Record("gateway_http_error", "")
		}
	}), "", 0)}
	listener, err := net.Listen("tcp", c.PublicListen)
	if err != nil {
		return errors.New("could not bind public listener")
	}
	defer listener.Close()
	privateListener, err := net.Listen("tcp", c.AdminListen)
	if err != nil {
		return errors.New("could not bind private administrative listener")
	}
	defer privateListener.Close()
	origin := strings.TrimSuffix(c.AdminURL, "/")
	if c.Development {
		origin = "http://" + privateListener.Addr().String()
	}
	dashboard, err = admin.NewHandler(store, g, admin.HandlerOptions{Origin: origin, Development: c.Development})
	if err != nil {
		return err
	}
	privateServer := &http.Server{Handler: dashboard, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}, ErrorLog: log.New(httpDiagnostics(func() { dashboard.Record("admin_http_error", "") }), "", 0)}
	defer privateServer.Close()
	defer server.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	served := make(chan error, 2)
	go func() {
		if c.TLSMode == "files" {
			served <- server.ServeTLS(listener, c.CertFile, c.KeyFile)
		} else {
			served <- server.Serve(listener)
		}
	}()
	go func() {
		if c.Development {
			served <- privateServer.Serve(privateListener)
		} else {
			served <- privateServer.ServeTLS(privateListener, c.AdminCertFile, c.AdminKeyFile)
		}
	}()
	fmt.Fprintln(os.Stderr, "Latch gateway listening on", listener.Addr())
	fmt.Fprintln(os.Stderr, "Latch administration listening on", privateListener.Addr())
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
