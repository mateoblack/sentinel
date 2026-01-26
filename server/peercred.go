// Package server provides local credential servers.
// peercred.go contains peer credential types for process-based authentication.
package server

import (
	"fmt"
	"net"
)

// PeerCredentials contains the credentials of a peer process connected via Unix socket.
// These credentials are obtained from the kernel via SO_PEERCRED (Linux) or
// LOCAL_PEERCRED (macOS) and cannot be spoofed by the connecting process.
type PeerCredentials struct {
	// PID is the process ID of the peer.
	PID int32

	// UID is the user ID of the peer.
	UID uint32

	// GID is the group ID of the peer.
	GID uint32
}

// String returns a human-readable representation of the credentials.
func (p *PeerCredentials) String() string {
	return fmt.Sprintf("pid=%d uid=%d gid=%d", p.PID, p.UID, p.GID)
}

// GetPeerCredentials extracts peer credentials from a Unix domain socket connection.
// Returns nil, nil if credentials cannot be obtained (e.g., non-Unix socket).
// Returns nil, error if there was an error extracting credentials.
//
// SECURITY: These credentials come directly from the kernel and cannot be
// spoofed by the connecting process. This is the basis for process-based
// authentication in local credential servers.
func GetPeerCredentials(conn net.Conn) (*PeerCredentials, error) {
	return getPeerCredentials(conn)
}

// ErrNotUnixSocket is returned when attempting to get peer credentials from
// a non-Unix socket connection.
type ErrNotUnixSocket struct {
	ConnType string
}

func (e *ErrNotUnixSocket) Error() string {
	return fmt.Sprintf("peer credentials only available for Unix sockets, got %s", e.ConnType)
}

// ErrPeerCredentialsUnavailable is returned when the platform does not support
// peer credential extraction.
type ErrPeerCredentialsUnavailable struct {
	Platform string
	Reason   string
}

func (e *ErrPeerCredentialsUnavailable) Error() string {
	return fmt.Sprintf("peer credentials unavailable on %s: %s", e.Platform, e.Reason)
}
