// Package licenses makes dependency notices available without network access.
package licenses

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
)

//go:embed notices.zip
var archive []byte

func Run(args []string) error {
	if len(args) == 0 {
		fmt.Println("Latch is MIT licensed. Third-party components retain their own licenses.")
		fmt.Println("Export original notices and dependency source references: licenses --output notices.zip")
		return nil
	}
	if len(args) != 2 || args[0] != "--output" || args[1] == "" {
		return errors.New("usage: licenses [--output NEW_ZIP_PATH]")
	}
	file, err := os.OpenFile(args[1], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(archive)
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		_ = os.Remove(args[1])
		return err
	}
	return nil
}
