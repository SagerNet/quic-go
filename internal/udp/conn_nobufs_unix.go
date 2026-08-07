//go:build unix

package udp

import (
	"errors"
	"syscall"
)

func IsNoBufferSpaceErr(err error) bool {
	return errors.Is(err, syscall.ENOBUFS)
}
