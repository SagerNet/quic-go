package udp

import (
	"io"
	"net"
	"syscall"
	"time"

	"github.com/sagernet/quic-go/internal/monotime"
	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/internal/utils"
)

type Capabilities struct {
	// This connection has the Don't Fragment (DF) bit set.
	// This means it makes to run DPLPMTUD.
	DF bool
	// GSO (Generic Segmentation Offload) supported
	GSO bool
	// ECN (Explicit Congestion Notifications) supported
	ECN bool
}

// Packet is a received UDP datagram.
type Packet struct {
	Buffer     *PacketBuffer
	RemoteAddr net.Addr
	RcvTime    monotime.Time
	Data       []byte
	ECN        protocol.ECN
	Info       PacketInfo
}

// Conn reads and writes UDP datagrams, including their ancillary data.
type Conn interface {
	ReadPacket() (Packet, error)
	// WritePacket writes a packet on the wire.
	// gsoSize is the size of a single packet, or 0 to disable GSO.
	// It is invalid to set gsoSize if capabilities.GSO is not set.
	WritePacket(b []byte, addr net.Addr, packetInfoOOB []byte, gsoSize uint16, ecn protocol.ECN) (int, error)
	LocalAddr() net.Addr
	SetReadDeadline(time.Time) error
	io.Closer

	Capabilities() Capabilities
}

// OOBCapablePacketConn is a connection that allows the reading of ECN bits from the IP header.
//
// Deprecated: all optimizations are now driven by the file descriptor alone; a conn only needs
// to implement syscall.Conn to enable them.
type OOBCapablePacketConn interface {
	net.PacketConn
	SyscallConn() (syscall.RawConn, error)
	SetReadBuffer(int) error
	ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error)
	WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (n, oobn int, err error)
}

var _ OOBCapablePacketConn = &net.UDPConn{}

// IOActivityConn is implemented by conns that observe their own I/O.
// On the optimized path, reads and writes go through the file descriptor and bypass the conn's
// own methods; these callbacks are invoked instead: onRead with the size of every received packet,
// onWrite with the number of bytes sent by every write.
type IOActivityConn interface {
	IOActivityFuncs() (onRead func(size int), onWrite func(size int))
}

// Wrap configures pc for UDP I/O.
// If pc already implements Conn, it is returned unchanged.
func Wrap(pc net.PacketConn) (Conn, error) {
	// Conn uses internal types, so only packages in this module (e.g. simnet) can implement it.
	if c, ok := pc.(Conn); ok {
		return c, nil
	}
	var sysConn syscall.RawConn
	syscallConn, isSyscallConn := pc.(syscall.Conn)
	if isSyscallConn {
		var err error
		sysConn, err = syscallConn.SyscallConn()
		if err != nil {
			sysConn = nil
		}
	}
	if sysConn == nil {
		utils.DefaultLogger.Infof("PacketConn is not a syscall.Conn. Disabling optimizations possible on UDP connections.")
		// Assume DF is set so that DPLPMTUD keeps working; the socket behind a
		// non-syscall conn is expected to have been configured by its owner.
		return &basicConn{PacketConn: pc, supportsDF: true}, nil
	}
	_ = setReceiveBuffer(sysConn)
	_ = setSendBuffer(sysConn)
	supportsDF := true
	if isDatagramSocket(sysConn) {
		var err error
		supportsDF, err = setDF(sysConn)
		if err != nil {
			return nil, err
		}
	}
	conn, err := newConn(pc, sysConn, supportsDF)
	if err != nil {
		utils.DefaultLogger.Infof("Failed to enable receive optimizations on the socket: %s. Disabling optimizations possible on UDP connections.", err)
		return &basicConn{PacketConn: pc, supportsDF: supportsDF}, nil
	}
	return conn, nil
}

// WrapConnected is the counterpart of Wrap for a connected packet-oriented net.Conn.
func WrapConnected(c net.Conn) (Conn, error) {
	var sysConn syscall.RawConn
	syscallConn, isSyscallConn := c.(syscall.Conn)
	if isSyscallConn {
		var err error
		sysConn, err = syscallConn.SyscallConn()
		if err != nil {
			sysConn = nil
		}
	}
	if sysConn == nil {
		utils.DefaultLogger.Infof("Conn is not a syscall.Conn. Disabling optimizations possible on UDP connections.")
		// Assume DF is set so that DPLPMTUD keeps working; the socket behind a
		// non-syscall conn is expected to have been configured by its owner.
		return &basicConnectedConn{Conn: c, remoteAddr: c.RemoteAddr(), supportsDF: true}, nil
	}
	_ = setReceiveBuffer(sysConn)
	_ = setSendBuffer(sysConn)
	supportsDF := true
	if isDatagramSocket(sysConn) {
		var err error
		supportsDF, err = setDF(sysConn)
		if err != nil {
			return nil, err
		}
	}
	conn, err := newConnectedConn(c, sysConn, supportsDF)
	if err != nil {
		utils.DefaultLogger.Infof("Failed to enable receive optimizations on the socket: %s. Disabling optimizations possible on UDP connections.", err)
		return &basicConnectedConn{Conn: c, remoteAddr: c.RemoteAddr(), supportsDF: supportsDF}, nil
	}
	return conn, nil
}

// The basicConn is the most trivial implementation of a rawConn.
// It reads a single packet from the underlying net.PacketConn.
// It is used when
// * the net.PacketConn is not a OOBCapablePacketConn, and
// * when the OS doesn't support OOB.
type basicConn struct {
	net.PacketConn
	supportsDF bool
}

var _ Conn = &basicConn{}

func (c *basicConn) ReadPacket() (Packet, error) {
	buffer := GetPacketBuffer()
	// The packet size should not exceed protocol.MaxReceivePacketSize bytes.
	// Larger packets are truncated and will fail decryption.
	buffer.Data = buffer.Data[:protocol.MaxReceivePacketSize]
	n, addr, err := c.ReadFrom(buffer.Data)
	if err != nil {
		buffer.Release()
		return Packet{}, err
	}
	return Packet{
		RemoteAddr: addr,
		RcvTime:    monotime.Now(),
		Data:       buffer.Data[:n],
		Buffer:     buffer,
	}, nil
}

func (c *basicConn) WritePacket(b []byte, addr net.Addr, _ []byte, gsoSize uint16, ecn protocol.ECN) (n int, err error) {
	if gsoSize != 0 {
		panic("cannot use GSO with a basicConn")
	}
	if ecn != protocol.ECNUnsupported {
		panic("cannot use ECN with a basicConn")
	}
	return c.WriteTo(b, addr)
}

func (c *basicConn) Capabilities() Capabilities { return Capabilities{DF: c.supportsDF} }

// The basicConnectedConn is the Conn for a connected conn whose file descriptor is not
// accessible. The remote address is fixed, so packets go through net.Conn's Read and Write.
type basicConnectedConn struct {
	net.Conn
	remoteAddr net.Addr
	supportsDF bool
}

var _ Conn = &basicConnectedConn{}

func (c *basicConnectedConn) ReadPacket() (Packet, error) {
	buffer := GetPacketBuffer()
	// The packet size should not exceed protocol.MaxReceivePacketSize bytes.
	// Larger packets are truncated and will fail decryption.
	buffer.Data = buffer.Data[:protocol.MaxReceivePacketSize]
	n, err := c.Read(buffer.Data)
	if err != nil {
		buffer.Release()
		return Packet{}, err
	}
	return Packet{
		RemoteAddr: c.remoteAddr,
		RcvTime:    monotime.Now(),
		Data:       buffer.Data[:n],
		Buffer:     buffer,
	}, nil
}

func (c *basicConnectedConn) WritePacket(b []byte, _ net.Addr, _ []byte, gsoSize uint16, ecn protocol.ECN) (int, error) {
	if gsoSize != 0 {
		panic("cannot use GSO with a basicConnectedConn")
	}
	if ecn != protocol.ECNUnsupported {
		panic("cannot use ECN with a basicConnectedConn")
	}
	return c.Write(b)
}

func (c *basicConnectedConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	if err != nil {
		return n, nil, err
	}
	return n, c.remoteAddr, nil
}

func (c *basicConnectedConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Write(p)
}

func (c *basicConnectedConn) Capabilities() Capabilities {
	return Capabilities{DF: c.supportsDF}
}
