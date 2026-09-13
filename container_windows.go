//go:build windows

package xmssmt

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// SYSTEM_INFO, see
// https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-system_info
type systemInfo struct {
	processorArchitecture     uint16
	reserved                  uint16
	pageSize                  uint32
	minimumApplicationAddress uintptr
	maximumApplicationAddress uintptr
	activeProcessorMask       uintptr
	numberOfProcessors        uint32
	processorType             uint32
	allocationGranularity     uint32
	processorLevel            uint16
	processorRevision         uint16
}

var (
	kernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemInfo = kernel32.NewProc("GetSystemInfo")
)

// Returns the granularity to which offsets passed to mmap must be aligned.
//
// On Windows, MapViewOfFile requires the file offset to be a multiple of
// the allocation granularity (typically 64KiB), which is larger than
// the page size (typically 4KiB) that os.Getpagesize() returns.
func mmapGranularity() int {
	var si systemInfo
	if err := procGetSystemInfo.Find(); err != nil {
		return 65536
	}
	procGetSystemInfo.Call(uintptr(unsafe.Pointer(&si)))
	if si.allocationGranularity == 0 {
		return 65536
	}
	return int(si.allocationGranularity)
}

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
