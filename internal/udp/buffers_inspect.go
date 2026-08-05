//go:build darwin || freebsd || linux || openbsd

package udp

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func inspectReadBuffer(c syscall.RawConn) (int, error) {
	var size int
	var serr error
	if err := c.Control(func(fd uintptr) {
		size, serr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
	}); err != nil {
		return 0, err
	}
	return size, serr
}

func inspectWriteBuffer(c syscall.RawConn) (int, error) {
	var size int
	var serr error
	if err := c.Control(func(fd uintptr) {
		size, serr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
	}); err != nil {
		return 0, err
	}
	return size, serr
}

func isDatagramSocket(c syscall.RawConn) bool {
	var socketType int
	var serr error
	err := c.Control(func(fd uintptr) {
		socketType, serr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TYPE)
	})
	return err == nil && serr == nil && socketType == unix.SOCK_DGRAM
}

func setReadBufferSize(c syscall.RawConn, bytes int) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, bytes)
	})
	if err != nil {
		return err
	}
	return serr
}

func setWriteBufferSize(c syscall.RawConn, bytes int) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, bytes)
	})
	if err != nil {
		return err
	}
	return serr
}
