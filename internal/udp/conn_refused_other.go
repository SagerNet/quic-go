//go:build !unix

package udp

func IsConnRefusedErr(error) bool { return false }
