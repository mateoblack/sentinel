//go:build linux

package server

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// getPeerCredentials extracts peer credentials using SO_PEERCRED on Linux.
// This works for Unix domain sockets (stream and datagram).
func getPeerCredentials(conn net.Conn) (*PeerCredentials, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, &ErrNotUnixSocket{ConnType: connTypeName(conn)}
	}

	// Get the raw file descriptor
	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("failed to get syscall conn: %w", err)
	}

	var ucred *unix.Ucred
	var ucredErr error

	err = rawConn.Control(func(fd uintptr) {
		ucred, ucredErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})

	if err != nil {
		return nil, fmt.Errorf("failed to control socket: %w", err)
	}
	if ucredErr != nil {
		return nil, fmt.Errorf("failed to get peer credentials: %w", ucredErr)
	}

	return &PeerCredentials{
		PID: ucred.Pid,
		UID: ucred.Uid,
		GID: ucred.Gid,
	}, nil
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
