//go:build unix

package udp

import (
	"errors"
	"syscall"
)

// A connected UDP socket reports an ICMP Port Unreachable message for one of its datagrams as
// ECONNREFUSED from the next send or receive call, and clears it once reported.
func IsConnRefusedErr(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
