//go:build ios

package quic

import "syscall"

// ReadBatch only returns a single packet without recvmsg_x,
// see https://godoc.org/golang.org/x/net/ipv4#PacketConn.ReadBatch.
const batchSize = 1

func isGSOEnabled(syscall.RawConn) bool { return false }
