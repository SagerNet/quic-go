//go:build linux

package udp

import "syscall"

func isUDPEOF(syscall.RawConn) bool {
	return false
}
