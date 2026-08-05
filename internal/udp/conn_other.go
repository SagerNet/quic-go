//go:build !darwin && !linux && !freebsd && !windows && !openbsd

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

func isDatagramSocket(syscall.RawConn) bool { return true }

func setReadBufferSize(syscall.RawConn, int) error  { return nil }
func setWriteBufferSize(syscall.RawConn, int) error { return nil }

func inspectReadBuffer(any) (int, error)  { return 0, nil }
func inspectWriteBuffer(any) (int, error) { return 0, nil }

const desiredBufferSize = 8 << 20 // 8 MiB
