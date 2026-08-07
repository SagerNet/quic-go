//go:build !unix && !windows

package udp

func IsNoBufferSpaceErr(error) bool {
	// to be implemented for more specific platforms
	return false
}
