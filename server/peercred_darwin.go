//go:build darwin

package server

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Constants for macOS LOCAL_PEERCRED
const (
	// SOL_LOCAL is the socket option level for local socket options on macOS.
	SOL_LOCAL = 0

	// LOCAL_PEERCRED retrieves peer credentials on macOS.
	// Returns xucred structure containing effective UID/GID.
	LOCAL_PEERCRED = 0x001
)

// xucred is the Darwin credential structure returned by LOCAL_PEERCRED.
// Note: Darwin doesn't provide PID via LOCAL_PEERCRED, only via LOCAL_PEERPID (separate call).
type xucred struct {
	Version uint32
	UID     uint32
	Ngroups int16
	Groups  [16]uint32 // NGROUPS = 16 on Darwin
}

const LOCAL_PEERPID = 0x002

// getPeerCredentials extracts peer credentials using LOCAL_PEERCRED on macOS.
// macOS requires two separate calls: LOCAL_PEERCRED for UID/GID and LOCAL_PEERPID for PID.
func getPeerCredentials(conn net.Conn) (*PeerCredentials, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, &ErrNotUnixSocket{ConnType: connTypeName(conn)}
	}

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("failed to get syscall conn: %w", err)
	}

	var creds PeerCredentials
	var credErr error

	err = rawConn.Control(func(fd uintptr) {
		// Get UID/GID via LOCAL_PEERCRED
		var xc xucred
		xcLen := uint32(unsafe.Sizeof(xc))
		_, _, errno := unix.Syscall6(
			unix.SYS_GETSOCKOPT,
			fd,
			SOL_LOCAL,
			LOCAL_PEERCRED,
			uintptr(unsafe.Pointer(&xc)),
			uintptr(unsafe.Pointer(&xcLen)),
			0,
		)
		if errno != 0 {
			credErr = fmt.Errorf("getsockopt LOCAL_PEERCRED failed: %v", errno)
			return
		}

		creds.UID = xc.UID
		if xc.Ngroups > 0 {
			creds.GID = xc.Groups[0] // Primary group
		}

		// Get PID via LOCAL_PEERPID
		var pid int32
		pidLen := uint32(unsafe.Sizeof(pid))
		_, _, errno = unix.Syscall6(
			unix.SYS_GETSOCKOPT,
			fd,
			SOL_LOCAL,
			LOCAL_PEERPID,
			uintptr(unsafe.Pointer(&pid)),
			uintptr(unsafe.Pointer(&pidLen)),
			0,
		)
		if errno != 0 {
			credErr = fmt.Errorf("getsockopt LOCAL_PEERPID failed: %v", errno)
			return
		}
		creds.PID = pid
	})

	if err != nil {
		return nil, fmt.Errorf("failed to control socket: %w", err)
	}
	if credErr != nil {
		return nil, credErr
	}

	return &creds, nil
}

func connTypeName(conn net.Conn) string {
	switch conn.(type) {
	case *net.TCPConn:
		return "TCP"
	case *net.UDPConn:
		return "UDP"
	case *net.UnixConn:
		return "Unix"
	default:
		return "unknown"
	}
}
