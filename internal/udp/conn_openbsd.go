//go:build openbsd

package udp

import (
	"net"
	"syscall"
)

func newConn(pc net.PacketConn, _ syscall.RawConn, supportsDF bool) (*basicConn, error) {
	return &basicConn{PacketConn: pc, supportsDF: supportsDF}, nil
}

func newConnectedConn(c net.Conn, _ syscall.RawConn, supportsDF bool) (*basicConnectedConn, error) {
	return &basicConnectedConn{Conn: c, remoteAddr: c.RemoteAddr(), supportsDF: supportsDF}, nil
}

// The OpenBSD kernel rejects socket buffer sizes larger than SB_MAX (2 MB, see sys/sys/socketvar.h)
// instead of clamping them. This limit is not queryable at runtime; changing it requires a custom
// kernel (sb_max is a patchable kernel variable, not a sysctl).
const desiredBufferSize = 2 << 20 // 2 MiB
