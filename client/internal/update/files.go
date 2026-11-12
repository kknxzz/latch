//go:build darwin || linux

package update

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func owned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}
func privateDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !owned(info) {
		return errors.New("update state must be an owned directory with mode 0700")
	}
	return nil
}
func lockExecutable(path string) (func(), error) {
	if os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		return nil, errors.New("updates cannot run with set-user or set-group privileges")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || !owned(info) || info.Mode().Perm()&0022 != 0 || info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return nil, errors.New("update executable must be owned by the current user and not writable by others")
	}
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil || !dir.IsDir() || !owned(dir) || dir.Mode().Perm()&0022 != 0 {
		return nil, errors.New("install Latch in a directory owned by the updating user and not writable by others")
	}
	fd, err := unix.Open(filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".update.lock"), unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "update lock")
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || !owned(info) || info.Mode().Perm() != 0600 {
		file.Close()
		return nil, errors.New("unsafe update lock")
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New("another update is already running")
	}
	return func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = file.Close() }, nil
}
func cacheFiles(path string) ([]os.DirEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	entries, err := file.ReadDir(129)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > 128 {
		return nil, errors.New("update cache file limit exceeded")
	}
	return entries, nil
}
func validateCache(path string) error {
	entries, err := cacheFiles(path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || !owned(info) || info.Mode().Perm()&0022 != 0 || info.Size() > 131072 {
			return errors.New("unsafe update metadata cache")
		}
	}
	return nil
}
func syncCache(path string) error {
	if err := validateCache(path); err != nil {
		return err
	}
	entries, err := cacheFiles(path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		file, err := os.OpenFile(filepath.Join(path, entry.Name()), os.O_RDWR, 0)
		if err != nil {
			return err
		}
		err = file.Sync()
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return syncDirectory(path)
}
func syncDirectory(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}
func installStage(stage, target string) (bool, error) {
	file, err := os.OpenFile(stage, os.O_RDWR, 0)
	if err != nil {
		return false, err
	}
	if err = file.Chmod(0755); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return false, err
	}
	if closeErr != nil {
		return false, closeErr
	}
	if err = os.Rename(stage, target); err != nil {
		return false, err
	}
	if err = syncDirectory(filepath.Dir(target)); err != nil {
		return true, fmt.Errorf("verified release was installed but directory synchronization failed: %w", err)
	}
	return true, nil
}
