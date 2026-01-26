//go:build !linux && !darwin

package server

import (
	"net"
	"runtime"
)

// getPeerCredentials returns an error on unsupported platforms.
// Windows does not support Unix domain socket peer credentials in the same way.
func getPeerCredentials(conn net.Conn) (*PeerCredentials, error) {
	return nil, &ErrPeerCredentialsUnavailable{
		Platform: runtime.GOOS,
		Reason:   "peer credentials require Unix domain sockets with SO_PEERCRED (Linux) or LOCAL_PEERCRED (macOS)",
	}
}
