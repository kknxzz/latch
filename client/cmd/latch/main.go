package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"latch.local/client/internal/app"
	"latch.local/client/internal/config"
	"latch.local/client/internal/identity"
	"latch.local/client/internal/licenses"
	"latch.local/client/internal/network"
	"latch.local/client/internal/tui"
	"latch.local/client/internal/update"
)

var version = "0.1.0-dev"

func main() {
	if err := run(os.Args[1:]); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "Latch:", err)
		os.Exit(1)
	}
}

type options struct {
	dir, server, endpoint, nick, backend, updateURL string
	dev, nickSet                                    bool
	enrollmentFD                                    int
}

func run(args []string) error {
	if len(args) > 0 && args[0] == "licenses" {
		return licenses.Run(args[1:])
	}
	if len(args) > 0 && args[0] == "update" {
		return runUpdate(args[1:])
	}
	if len(args) == 1 && args[0] == "version" {
		fmt.Println("Latch", version)
		return nil
	}
	if len(args) == 2 && args[0] == "version" && args[1] == "--json" {
		rootHash := ""
		if root, err := update.EmbeddedRoot(); err == nil {
			rootHash = fmt.Sprintf("%x", sha256.Sum256(root))
		}
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"version": version, "os": runtime.GOOS, "arch": runtime.GOARCH, "protocol": 1, "root_sha256": rootHash})
	}
	enrollOnly := len(args) > 0 && args[0] == "enroll"
	if enrollOnly {
		args = args[1:]
	}
	flags := flag.NewFlagSet("latch", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	var o options
	flags.StringVar(&o.dir, "config-dir", "", "Isolated client configuration directory")
	flags.StringVar(&o.server, "server", "", "Server HTTPS URL for first enrollment")
	flags.StringVar(&o.endpoint, "endpoint", "/c/", "WebSocket endpoint")
	flags.StringVar(&o.nick, "nick", "", "Optional nickname")
	flags.StringVar(&o.backend, "identity-backend", "", "Credential storage: keychain or file")
	flags.StringVar(&o.updateURL, "update-url", "", "Explicit HTTPS software release repository")
	flags.BoolVar(&o.dev, "dev", false, "Permit loopback-only cleartext development")
	flags.IntVar(&o.enrollmentFD, "enrollment-fd", -1, "Read enrollment code from an inherited descriptor, >=3")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected arguments; use /help inside Latch")
	}
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "nick" {
			o.nickSet = true
		}
	})
	if o.enrollmentFD != -1 && o.enrollmentFD < 3 {
		return errors.New("enrollment descriptor must be at least 3")
	}
	if o.updateURL != "" {
		var err error
		o.updateURL, err = update.NormalizeRepository(o.updateURL)
		if err != nil {
			return err
		}
	}
	if o.dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return err
		}
		o.dir = filepath.Join(base, "latch")
	}
	dir, err := filepath.Abs(o.dir)
	if err != nil {
		return err
	}
	o.dir = dir
	identityLock, err := config.LockIdentity(o.dir)
	if err != nil {
		return err
	}
	defer identityLock.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// /dev/tty permits prompts when the installer itself was read from a pipe.
	tty, ttyErr := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if ttyErr == nil {
		defer tty.Close()
	}
	c, id, err := prepareIdentity(ctx, o, tty)
	if err != nil {
		return err
	}
	defer id.Clear()
	client := network.New(c)
	defer func() { client.Close() }()
	conn, err := client.Connect(ctx, id)
	if errors.Is(err, network.ErrRejected) && !c.Enrolled {
		code, e := enrollmentCode(ctx, o.enrollmentFD, tty)
		if e != nil {
			return e
		}
		enrollErr := client.Enroll(ctx, id, code)
		code = ""
		// A successful enrollment with a lost HTTP response is recovered by key auth.
		conn, err = client.Connect(ctx, id)
		if err != nil {
			if enrollErr != nil {
				return enrollErr
			}
			return err
		}
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	if !c.Enrolled || o.nickSet || o.updateURL != "" {
		c.Enrolled = true
		if err = config.Save(o.dir, c); err != nil {
			return err
		}
	}
	if enrollOnly {
		return nil
	}
	if ttyErr != nil {
		return errors.New("interactive terminal required")
	}
	terminal, err := tui.New(tty, tty, os.Getenv("NO_COLOR") == "")
	if err != nil {
		return err
	}
	defer terminal.Close()
	saveNick := func(nick string) error { c.Nickname = nick; return config.Save(o.dir, c) }
	for {
		model := app.New(id, c.ServerURL, c.Nickname, conn, saveNick)
		err = app.Run(ctx, model, conn, terminal.Events(), terminal.Render)
		if err == nil {
			return nil
		}
		if !errors.Is(err, network.ErrClosed) {
			return err
		}
		for attempt := 0; ; attempt++ {
			terminal.Render(app.Snapshot{Server: c.ServerURL, DeviceID: id.DeviceID(), Nickname: c.Nickname, Status: "Reconnecting", Prompt: "> ", Lines: []app.Line{{Time: time.Now(), Text: "Connection lost. The previous room has ended.", System: true}}})
			if err = waitReconnect(ctx, terminal.Events(), min(15*time.Second, time.Second<<min(attempt, 4))); err != nil {
				return nil
			}
			// Refresh configuration after a nickname change before reconnecting.
			client.Close()
			client = network.New(c)
			conn, err = client.Connect(ctx, id)
			if err == nil {
				break
			}
			if errors.Is(err, network.ErrRejected) || errors.Is(err, network.ErrServerChanged) || errors.Is(err, network.ErrProtocol) {
				return err
			}
		}
	}
}

func prepareIdentity(ctx context.Context, o options, tty *os.File) (config.Config, identity.Identity, error) {
	c, err := config.Load(o.dir)
	if err == nil {
		if o.server != "" {
			base, _, e := config.Normalize(o.server, c.Endpoint, c.Development)
			if e != nil || base != c.ServerURL {
				return c, identity.Identity{}, errors.New("use a separate --config-dir for another server")
			}
		}
		if o.backend != "" && o.backend != c.IdentityBackend {
			return c, identity.Identity{}, errors.New("credential backend changes require an explicit identity migration")
		}
		backend, e := backendFor(c.IdentityBackend, o.dir)
		if e != nil {
			return c, identity.Identity{}, e
		}
		id, e := identity.Load(backend, c.IdentityAccount)
		if e != nil {
			return c, identity.Identity{}, e
		}
		if id.ServerID != c.ServerID || (c.IdentityAccount != "" && id.UUID != c.IdentityAccount) {
			id.Clear()
			return c, identity.Identity{}, identity.ErrInvalid
		}
		if o.nickSet {
			if !identity.ValidNickname(o.nick) {
				id.Clear()
				return c, identity.Identity{}, config.ErrInvalid
			}
			c.Nickname = o.nick
		}
		if o.updateURL != "" {
			c.UpdateURL = o.updateURL
		}
		return c, id, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return c, identity.Identity{}, err
	}
	if _, e := os.Lstat(filepath.Join(o.dir, "identity.json")); e == nil {
		return c, identity.Identity{}, errors.New("identity exists without configuration; restore its configuration before continuing")
	}
	server := o.server
	if server == "" {
		if tty == nil {
			return c, identity.Identity{}, errors.New("first enrollment requires --server or a terminal")
		}
		server, err = tui.Prompt(ctx, tty, "Server URL: ", false)
		if err != nil {
			return c, identity.Identity{}, err
		}
	}
	base, endpoint, err := config.Normalize(server, o.endpoint, o.dev)
	if err != nil {
		return c, identity.Identity{}, err
	}
	nick := o.nick
	if !o.nickSet && tty != nil && o.enrollmentFD == -1 {
		nick, err = tui.Prompt(ctx, tty, "Nickname (Optional): ", false)
		if err != nil {
			return c, identity.Identity{}, err
		}
	}
	if !identity.ValidNickname(nick) {
		return c, identity.Identity{}, config.ErrInvalid
	}
	backendName := o.backend
	if backendName == "" {
		_, backendName = identity.DefaultBackend(o.dir)
	}
	backend, err := backendFor(backendName, o.dir)
	if err != nil {
		return c, identity.Identity{}, err
	}
	c = config.Config{ServerURL: base, Endpoint: endpoint, Nickname: nick, Development: o.dev, IdentityBackend: backendName, UpdateURL: o.updateURL}
	client := network.New(c)
	defer client.Close()
	info, err := client.Info(ctx)
	if err != nil {
		return c, identity.Identity{}, err
	}
	c.ServerID = info.ServerID
	id, err := identity.Generate(info.ServerID)
	if err != nil {
		return c, id, err
	}
	c.IdentityAccount = id.UUID
	if err = identity.Save(backend, c.IdentityAccount, id); err != nil {
		id.Clear()
		return c, identity.Identity{}, err
	}
	if err = config.Save(o.dir, c); err != nil {
		id.Clear()
		return c, identity.Identity{}, err
	}
	return c, id, nil
}
func backendFor(name, dir string) (identity.Backend, error) {
	switch name {
	case "file":
		return identity.FileBackend{Dir: dir}, nil
	case "keychain":
		return identity.NativeBackend()
	default:
		return nil, config.ErrInvalid
	}
}
func enrollmentCode(ctx context.Context, fd int, tty *os.File) (string, error) {
	var code string
	var err error
	if fd >= 3 {
		file := os.NewFile(uintptr(fd), "enrollment input")
		if file == nil {
			return "", errors.New("invalid enrollment descriptor")
		}
		defer file.Close()
		info, e := file.Stat()
		if e != nil {
			return "", errors.New("invalid enrollment descriptor")
		}
		if info.Mode().IsRegular() && info.Mode().Perm()&0077 != 0 {
			return "", errors.New("enrollment input file must be private")
		}
		data, e := tui.ReadCredential(ctx, file)
		if e != nil {
			clear(data)
			return "", errors.New("invalid enrollment input")
		}
		code = strings.TrimSpace(string(data))
		clear(data)
	} else {
		if tty == nil {
			return "", errors.New("enrollment requires a terminal or --enrollment-fd")
		}
		code, err = tui.Prompt(ctx, tty, "Enrollment code: ", true)
		if err != nil {
			return "", err
		}
	}
	if len(code) != 6 {
		return "", errors.New("enrollment code must contain six digits")
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return "", errors.New("enrollment code must contain six digits")
		}
	}
	return code, nil
}
func waitReconnect(ctx context.Context, inputs <-chan app.Command, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		case input, ok := <-inputs:
			if !ok || input.Quit || input.Text == "/quit" || input.Text == "/exit" {
				return app.ErrQuit
			}
		}
	}
}
