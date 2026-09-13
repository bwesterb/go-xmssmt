//go:build !windows

package xmssmt

import (
	"os"
	"path/filepath"
)

// Returns the granularity to which offsets passed to mmap must be aligned.
func mmapGranularity() int {
	return os.Getpagesize()
}

// Renames tmp over dst and syncs the parent directory, so that the rename
// itself is durable.  If the sync fails we have no way of knowing whether
// the change has been written out to disk.
func renameDurably(tmp, dst string) error {
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(dst))
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		dir.Close()
		return err
	}
	return dir.Close()
}
