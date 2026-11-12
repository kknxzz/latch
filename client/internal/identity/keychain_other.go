//go:build !darwin

package identity

import "errors"

func DefaultBackend(dir string) (Backend, string) { return FileBackend{Dir: dir}, "file" }
func NativeBackend() (Backend, error) {
	return nil, errors.New("native credential storage is unavailable on this platform")
}
