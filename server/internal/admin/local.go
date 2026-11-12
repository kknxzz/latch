// Package admin serves privileged administration separately from the public API.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"latch.local/server/internal/auth"
	"latch.local/server/internal/protocol"
)

type Local struct {
	listener       *net.UnixListener
	store          *auth.Store
	slots          chan struct{}
	credentialSlot chan struct{}
	done           chan struct{}
	workers        sync.WaitGroup
	once           sync.Once
}
type LocalRequest struct {
	Operation    string `json:"operation"`
	Password     []byte `json:"password,omitempty"`
	TOTPSecret   string `json:"totp_secret,omitempty"`
	Confirmation string `json:"confirmation,omitempty"`
}
type LocalResponse struct {
	Code      string    `json:"code,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Error     string    `json:"error,omitempty"`
	ServerID  string    `json:"server_id,omitempty"`
}

// ListenLocal requires the same private directory as the locked database. The
// filesystem's owner-only socket permissions authorize the local service user
// and root. This interface is never bound to TCP or exposed through the proxy.
func ListenLocal(store *auth.Store, dir string) (*Local, error) {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, errors.New("local administration requires a private state directory")
	}
	path := filepath.Join(dir, "admin.sock")
	if len(path) > 100 {
		return nil, errors.New("state directory path is too long for local administration; choose a shorter path")
	}
	if old, e := os.Lstat(path); e == nil {
		if old.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("unsafe local administration socket path")
		}
		// The caller already owns the exclusively locked state DB, so a previous
		// daemon cannot be serving this state. Remove only a stale socket, not files.
		if e = os.Remove(path); e != nil {
			return nil, e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, 0600); err != nil {
		listener.Close()
		return nil, err
	}
	local := &Local{listener: listener, store: store, slots: make(chan struct{}, 4), credentialSlot: make(chan struct{}, 1), done: make(chan struct{})}
	go local.serve()
	return local, nil
}
func (l *Local) serve() {
	defer close(l.done)
	for {
		conn, err := l.listener.AcceptUnix()
		if err != nil {
			return
		}
		select {
		case l.slots <- struct{}{}:
			l.workers.Add(1)
			go func() { defer l.workers.Done(); defer func() { <-l.slots }(); l.handle(conn) }()
		default:
			conn.Close()
		}
	}
}
func (l *Local) handle(conn *net.UnixConn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	// A newline-delimited single request avoids waiting for EOF on a connection
	// whose caller is waiting for the response. Bound the entire request to 1 KiB.
	data := make([]byte, 0, 128)
	defer func() { clear(data) }()
	var one [1]byte
	for len(data) <= 1024 {
		n, err := conn.Read(one[:])
		if n == 1 {
			if one[0] == '\n' {
				break
			}
			data = append(data, one[0])
		}
		if err != nil {
			return
		}
	}
	var request LocalRequest
	defer func() { clear(request.Password) }()
	response := LocalResponse{}
	if len(data) > 1024 || protocol.Strict(data, &request) != nil {
		response.Error = "Invalid local request."
	} else {
		switch request.Operation {
		case "server.info":
			response.ServerID = l.store.ServerID()
		case "admin.initialize", "admin.reset":
			select {
			case l.credentialSlot <- struct{}{}:
				err := Initialize(l.store, request.Password, request.TOTPSecret, request.Confirmation, time.Now(), request.Operation == "admin.reset")
				<-l.credentialSlot
				if err != nil {
					if errors.Is(err, auth.ErrAdminInitialized) {
						response.Error = "Administrator already initialized."
					} else {
						response.Error = "Administrator initialization failed."
					}
				}
			default:
				response.Error = "Administrator initialization busy."
			}
		case "enrollment.generate":
			code, expires, err := l.store.GenerateCode()
			if err != nil {
				response.Error = "Enrollment generation failed."
			} else {
				response.Code = code
				response.ExpiresAt = expires
			}
		default:
			response.Error = "Unsupported local operation."
		}
	}
	_ = json.NewEncoder(conn).Encode(response)
}
func (l *Local) Close() error {
	var err error
	l.once.Do(func() { err = l.listener.Close(); <-l.done; l.workers.Wait() })
	return err
}

func CallLocal(ctx context.Context, dir, operation string) (LocalResponse, error) {
	return RequestLocal(ctx, dir, LocalRequest{Operation: operation})
}
func RequestLocal(ctx context.Context, dir string, request LocalRequest) (LocalResponse, error) {
	var response LocalResponse
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return response, errors.New("unsafe local administration directory")
	}
	path := filepath.Join(dir, "admin.sock")
	info, err = os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 {
		return response, errors.New("local administration unavailable")
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return response, errors.New("local administration unavailable")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if json.NewEncoder(conn).Encode(request) != nil {
		return response, errors.New("local administration request failed")
	}
	data, err := io.ReadAll(io.LimitReader(conn, 2049))
	if err != nil || len(data) > 2048 || protocol.Strict(data, &response) != nil {
		return response, errors.New("invalid local administration response")
	}
	if response.Error != "" {
		return response, errors.New("local administration request rejected")
	}
	return response, nil
}
