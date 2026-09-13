//go:build windows

package xmssmt

import (
	"golang.org/x/sys/windows"
)

// Renames tmp over dst such that the rename itself is durable.
//
// Windows does not support syncing a directory (FlushFileBuffers fails on
// a directory handle), so instead we ask MoveFileEx to write the rename
// through to disk before returning.
func renameDurably(tmp, dst string) error {
	from, err := windows.UTF16PtrFromString(tmp)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(dst)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
