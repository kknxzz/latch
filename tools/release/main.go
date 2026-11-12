package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Latch release:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: latch-release init|inspect|publish")
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	keys := flags.String("keys-dir", "", "Protected operator signing directory")
	switch args[0] {
	case "inspect":
		binary := flags.String("binary", "", "Absolute locally built executable path")
		target := flags.String("target", "", "Exact native artifact name")
		root := flags.String("root", "", "Independently verified public TUF root")
		version := flags.String("version", "", "Stable release version")
		commit := flags.String("source-commit", "", "Exact source commit")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected arguments")
		}
		return inspect(*binary, *target, *root, *version, *commit)
	case "init":
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected arguments")
		}
		fingerprint, err := initKeys(*keys)
		if err != nil {
			return err
		}
		fmt.Println("Publisher SHA-256 fingerprint:", fingerprint)
		fmt.Println("Move root-1.pem, root-2.pem and root-3.pem into separate offline storage before publication.")
		return nil
	case "publish":
		p := publication{}
		flags.StringVar(&p.Artifacts, "artifacts", "", "Directory containing all six validated native binaries")
		flags.StringVar(&p.Output, "output", "", "Public release output directory")
		flags.StringVar(&p.Version, "version", "", "Stable release version")
		flags.StringVar(&p.Commit, "source-commit", "", "Exact source commit")
		flags.StringVar(&p.ClientScript, "client-script", "", "Client bootstrap source")
		flags.StringVar(&p.ServerScript, "server-script", "", "Server installer source")
		flags.StringVar(&p.ServerUnit, "server-unit", "", "Server systemd service unit")
		flags.StringVar(&p.License, "license", "", "MIT license file")
		expires := flags.String("expires", "", "Explicit RFC3339 manifest/target expiry within eight days")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("unexpected arguments")
		}
		p.Keys = *keys
		var err error
		p.Expires, err = time.Parse(time.RFC3339, *expires)
		if err != nil {
			return errors.New("supply --expires as an explicit RFC3339 time")
		}
		if err = publish(p); err != nil {
			return err
		}
		fmt.Println("Signed release files written:", p.Output)
		return nil
	default:
		return errors.New("unknown release command")
	}
}
