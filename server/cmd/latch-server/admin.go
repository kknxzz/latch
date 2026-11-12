package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"latch.local/server/internal/admin"
	"latch.local/server/internal/auth"
	"latch.local/server/internal/config"
	"latch.local/server/internal/protocol"
)

type adminInput struct {
	Password     string `json:"password"`
	Secret       string `json:"totp_secret"`
	Confirmation string `json:"confirmation"`
}

func runAdmin(args []string) error {
	if len(args) == 0 || (args[0] != "init" && args[0] != "reset") {
		return errors.New("usage: latch-server admin init|reset --state-dir DIR")
	}
	replace := args[0] == "reset"
	flags := flag.NewFlagSet("admin", flag.ContinueOnError)
	dir := flags.String("state-dir", "", "Private server state directory")
	configPath := flags.String("config", "", "Protected server configuration")
	inputFD := flags.Int("credentials-fd", -1, "Private regular-file descriptor for automated setup, >=3")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || (*dir == "") == (*configPath == "") {
		return errors.New("choose --state-dir or --config")
	}
	if *inputFD != -1 && *inputFD < 3 {
		return errors.New("credentials descriptor must be at least 3")
	}
	if *configPath != "" {
		c, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		*dir = c.StateDir
	}
	absolute, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	info, localErr := admin.CallLocal(ctx, absolute, "server.info")
	var store *auth.Store
	serverID := info.ServerID
	if localErr != nil {
		store, err = auth.Open(filepath.Join(absolute, "state.db"), nil)
		if err != nil {
			return errors.New("could not access local server state")
		}
		defer store.Close()
		serverID = store.ServerID()
	}
	var password []byte
	var secret, confirmation string
	if *inputFD >= 3 {
		file := os.NewFile(uintptr(*inputFD), "administrator credentials")
		if file == nil {
			return errors.New("invalid credentials descriptor")
		}
		defer file.Close()
		stat, err := file.Stat()
		if err != nil || !stat.Mode().IsRegular() || stat.Mode().Perm()&0077 != 0 || stat.Size() > 1024 {
			return errors.New("credentials descriptor must reference a private regular file of at most 1024 bytes")
		}
		data, err := io.ReadAll(io.LimitReader(file, 1025))
		if err != nil {
			return errors.New("credentials read failed")
		}
		defer clear(data)
		var input adminInput
		if protocol.Strict(data, &input) != nil {
			return errors.New("invalid administrator credentials input")
		}
		password = []byte(input.Password)
		input.Password = ""
		secret = input.Secret
		confirmation = input.Confirmation
	} else {
		tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			return errors.New("administrator setup requires a terminal or --credentials-fd")
		}
		defer tty.Close()
		_, _ = fmt.Fprintln(tty, "Latch Administrator Setup\r\nUse a password with at least 16 characters.")
		password, err = admin.ReadSecret(ctx, tty, "Password: ")
		if err != nil {
			return err
		}
		defer clear(password)
		confirm, err := admin.ReadSecret(ctx, tty, "Confirm Password: ")
		if err != nil {
			return err
		}
		matched := subtle.ConstantTimeCompare(password, confirm) == 1
		clear(confirm)
		if !matched {
			return errors.New("passwords do not match")
		}
		secret, err = admin.NewTOTPSecret()
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintln(tty, "Add this key to your authenticator (Issuer: Latch):\r\n"+secret+"\r\n"+admin.TOTPURI(secret, serverID))
		code, err := admin.ReadSecret(ctx, tty, "Authenticator Code: ")
		if err != nil {
			return err
		}
		confirmation = string(code)
		clear(code)
	}
	defer clear(password)
	if store != nil {
		err = admin.Initialize(store, password, secret, confirmation, time.Now(), replace)
	} else {
		operation := "admin.initialize"
		if replace {
			operation = "admin.reset"
		}
		_, err = admin.RequestLocal(ctx, absolute, admin.LocalRequest{Operation: operation, Password: password, TOTPSecret: secret, Confirmation: confirmation})
	}
	if err != nil {
		return err
	}
	fmt.Println("Administrator configured. Use the next authenticator code to sign in.")
	return nil
}
