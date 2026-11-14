package main

import (
	"archive/tar"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

func main() {
	dir := flag.String("directory", "", "signed publication directory")
	output := flag.String("output", "", "new archive")
	arch := flag.String("arch", "", "optional server architecture")
	epoch := flag.Int64("epoch", 0, "source epoch")
	flag.Parse()
	if err := bundle(*dir, *output, *arch, time.Unix(*epoch, 0).UTC()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func bundle(dir, output, arch string, epoch time.Time) error {
	names := []string{}
	if arch != "" {
		if arch != "amd64" && arch != "arm64" {
			return fmt.Errorf("invalid architecture")
		}
		binary := "latch-server-linux-" + arch
		names = []string{"start.sh", "start.sh.sig", "server-install.sh", "server-install.sh.sig", "latch-server.service", "manifest.txt", "manifest.sig", "publisher.pub", "root.json", "LICENSE", binary, binary + ".build.json", binary + ".environment.json"}
	} else {
		if err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			name, err := filepath.Rel(dir, path)
			if err == nil {
				names = append(names, name)
			}
			return err
		}); err != nil {
			return err
		}
	}
	sort.Strings(names)
	out, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer out.Close()
	gz := gzip.NewWriter(out)
	gz.Header.OS = 255
	tw := tar.NewWriter(gz)
	for _, name := range names {
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > 67108864 {
			return fmt.Errorf("unsafe archive input %s", name)
		}
		if err := tw.WriteHeader(&tar.Header{Name: filepath.ToSlash(name), Mode: 0644, Size: info.Size(), ModTime: epoch, Format: tar.FormatUSTAR}); err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		_, err = io.CopyN(tw, f, info.Size())
		f.Close()
		if err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return out.Sync()
}
