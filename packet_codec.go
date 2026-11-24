package quic

import (
	"net"

	"github.com/sagernet/quic-go/internal/protocol"
)

// A PacketCodec converts between the QUIC packets of a [Transport] and the datagrams carrying them.
type PacketCodec interface {
	// Encode writes the datagrams carrying the QUIC packet b through write, without modifying b.
	// It is called concurrently.
	Encode(b []byte, write func(datagram []byte) error) error
	// Decode returns the QUIC packet carried by the datagram b received from addr, or false if
	// there is none. It may decode in place and use the full capacity of b.
	Decode(b []byte, addr net.Addr) ([]byte, bool)
}

type codecConn struct {
	rawConn
	codec       PacketCodec
	interceptor func(b []byte, addr net.Addr) bool
}

var _ rawConn = &codecConn{}

func (c *codecConn) ReadPacket() (receivedPacket, error) {
	for {
		p, err := c.rawConn.ReadPacket()
		if err != nil || len(p.data) == 0 {
			return p, err
		}
		if c.interceptor != nil && c.interceptor(p.data, p.remoteAddr) {
			p.buffer.Release()
			continue
		}
		if c.codec != nil {
			data, ok := c.codec.Decode(p.data, p.remoteAddr)
			if !ok {
				p.buffer.Release()
				continue
			}
			p.data = data
		}
		return p, nil
	}
}

func (c *codecConn) WritePacket(b []byte, addr net.Addr, packetInfoOOB []byte, gsoSize uint16, ecn protocol.ECN) (int, error) {
	if c.codec == nil {
		return c.rawConn.WritePacket(b, addr, packetInfoOOB, gsoSize, ecn)
	}
	err := c.codec.Encode(b, func(datagram []byte) error {
		_, err := c.rawConn.WritePacket(datagram, addr, packetInfoOOB, 0, protocol.ECNUnsupported)
		return err
	})
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *codecConn) capabilities() connCapabilities {
	capabilities := c.rawConn.capabilities()
	if c.codec != nil {
		capabilities.DF = false
		capabilities.GSO = false
		capabilities.ECN = false
	}
	return capabilities
}
