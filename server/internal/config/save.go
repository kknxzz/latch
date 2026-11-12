package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// SaveNew publishes a complete private configuration without replacing an
// existing file. A failed setup never truncates a working configuration.
func SaveNew(path string, c Config) error {
	if !filepath.IsAbs(path) {
		return ErrInvalid
	}
	if err := c.Validate(); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := PrivateDir(dir); err != nil {
		return err
	}
	file, err := os.CreateTemp(dir, ".config-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err = json.NewEncoder(file).Encode(c); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Link(file.Name(), path); err != nil {
		return errors.New("configuration already exists or cannot be published")
	}
	folder, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer folder.Close()
	return folder.Sync()
}
