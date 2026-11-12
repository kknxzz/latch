package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"latch.local/client/internal/config"
	"latch.local/client/internal/update"
)

func runUpdate(args []string) error {
	flags := flag.NewFlagSet("update", flag.ContinueOnError)
	dir := flags.String("config-dir", "", "Client configuration directory")
	repository := flags.String("repository", "", "HTTPS release repository (defaults to saved update_url)")
	rootPath := flags.String("trust-root", "", "Explicit, independently verified public TUF root file")
	check := flags.Bool("check", false, "Verify whether a newer release exists without downloading its binary")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected update arguments")
	}
	if *dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return err
		}
		*dir = filepath.Join(base, "latch")
	}
	absolute, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	c, err := config.Load(absolute)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if *repository == "" {
		*repository = c.UpdateURL
	}
	if *repository == "" {
		return errors.New("configure update_url or supply --repository with your release repository")
	}
	var root []byte
	if *rootPath != "" {
		info, err := os.Lstat(*rootPath)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 65536 {
			return errors.New("trust root must be a protected regular file of at most 64 KiB")
		}
		root, err = os.ReadFile(*rootPath)
		if err != nil {
			return err
		}
	} else {
		root, err = update.EmbeddedRoot()
		if err != nil {
			return err
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, err := update.Run(ctx, update.Options{RepositoryURL: *repository, StateDir: filepath.Join(absolute, "updates"), CurrentVersion: version, Root: root, CheckOnly: *check})
	if err != nil {
		return err
	}
	switch {
	case result.Current:
		fmt.Println("Latch", result.Version, "is already installed.")
	case result.Installed:
		fmt.Println("Installed Latch", result.Version+". New sessions will use this version.")
	default:
		fmt.Println("Verified Latch", result.Version, "is available. Run latch update without --check to install.")
	}
	return nil
}
