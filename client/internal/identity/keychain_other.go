//go:build !darwin

package identity

func DefaultBackend(dir string) (Backend, string) { return FileBackend{Dir: dir}, "file" }
