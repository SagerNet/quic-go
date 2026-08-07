//go:build linux || freebsd

package udp

import "syscall"

func newBatchReader(syscall.RawConn, bool) batchConn { return nil }

func newSegmentWriter(syscall.RawConn) segmentWriter { return nil }
