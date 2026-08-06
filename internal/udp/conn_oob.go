//go:build darwin || linux || freebsd

package udp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/sagernet/quic-go/internal/monotime"
	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/internal/utils"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

const (
	ecnMask       = 0x3
	oobBufferSize = 128
)

// Contrary to what the naming suggests, the ipv{4,6}.Message is not dependent on the IP version.
// They're both just aliases for x/net/internal/socket.Message.
// This means we can use this struct to read from a socket that receives both IPv4 and IPv6 messages.
var _ ipv4.Message = ipv6.Message{}

type batchConn interface {
	ReadBatch(ms []ipv4.Message, flags int) (int, error)
}

// segmentWriter sends the segments of a GSO buffer as a batch of datagrams, on platforms that
// have a batched sendmsg but no kernel segmentation offload.
type segmentWriter interface {
	// WriteSegments writes b as datagrams of segmentSize bytes each, the last one possibly
	// shorter, all carrying oob. sockaddr is nil on a connected socket.
	WriteSegments(b []byte, segmentSize int, sockaddr unix.Sockaddr, oob []byte) (int, error)
}

// udpCompatConn makes a conn whose file descriptor was obtained through the syscall.Conn
// contract acceptable to x/net: socket.NewConn (x/net/internal/socket/rawconn.go) classifies
// a conn as UDP by asserting net.UDPConn's SyscallConn+ReadMsgUDP method pair and then only
// uses the file descriptor; ReadMsgUDP is a marker there and is never called on the batch
// read path. ipv4.NewPacketConn additionally asserts net.Conn on its argument.
type udpCompatConn struct {
	net.PacketConn
	sysConn syscall.RawConn
}

func (c *udpCompatConn) SyscallConn() (syscall.RawConn, error) { return c.sysConn, nil }

func (c *udpCompatConn) ReadMsgUDP(b, oob []byte) (n, oobn, flags int, addr *net.UDPAddr, err error) {
	return 0, 0, 0, nil, errors.ErrUnsupported
}

func (c *udpCompatConn) Read(b []byte) (int, error) {
	n, _, err := c.ReadFrom(b)
	return n, err
}

func (c *udpCompatConn) Write(b []byte) (int, error) { return 0, errors.ErrUnsupported }

func (c *udpCompatConn) RemoteAddr() net.Addr { return nil }

// connectedCompatConn is udpCompatConn's counterpart for connected conns. The SetLinger
// marker makes socket.NewConn classify the conn as "tcp", which drops the per-message name
// buffers from both directions of the recvmmsg/sendmmsg paths (x/net/internal/socket/
// rawconn_mmsg.go gates the address marshal/parse functions on the network, while control
// message buffers are handled unconditionally) — a connected socket needs no address per
// packet, and skipping the name parse avoids a *net.UDPAddr allocation per received packet.
type connectedCompatConn struct {
	net.Conn
	sysConn syscall.RawConn
}

func (c *connectedCompatConn) SyscallConn() (syscall.RawConn, error) { return c.sysConn, nil }

func (c *connectedCompatConn) SetLinger(int) error { return nil }

func (c *connectedCompatConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.Read(p)
	if err != nil {
		return n, nil, err
	}
	return n, c.RemoteAddr(), nil
}

func (c *connectedCompatConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.Write(p)
}

func isECNDisabledUsingEnv() bool {
	disabled, err := strconv.ParseBool(os.Getenv("QUIC_GO_DISABLE_ECN"))
	return err == nil && disabled
}

type oobConn struct {
	net.PacketConn
	sysConn       syscall.RawConn
	batchConn     batchConn
	segmentWriter segmentWriter
	ipv4Socket    bool

	// Set when the socket is connected: the fixed remote address, delivered with every
	// received packet, and its normalized form used to reject writes to other addresses.
	remoteAddr     net.Addr
	remoteAddrPort netip.AddrPort

	readPos uint8
	// Packets received from the kernel, but not yet returned by ReadPacket().
	messages []ipv4.Message
	buffers  [batchSize]*PacketBuffer

	// Cache of the last WritePacket destination's sockaddr conversion, keyed by pointer:
	// each connection's send path reuses one *net.UDPAddr object per remote, while the
	// packet conn itself is shared by every connection on the Transport.
	writeSockaddrCache atomic.Pointer[writeSockaddrEntry]

	cap Capabilities
}

type writeSockaddrEntry struct {
	addr     *net.UDPAddr
	sockaddr unix.Sockaddr
	ipv4     bool
}

var _ Conn = &oobConn{}

func newConn(pc net.PacketConn, sysConn syscall.RawConn, supportsDF bool) (*oobConn, error) {
	var needsPacketInfo bool
	if udpAddr, ok := pc.LocalAddr().(*net.UDPAddr); ok && udpAddr.IP.IsUnspecified() {
		needsPacketInfo = true
	}
	// We don't know if this a IPv4-only, IPv6-only or a IPv4-and-IPv6 connection.
	// Try enabling receiving of ECN and packet info for both IP versions.
	// We expect at least one of those syscalls to succeed.
	var ipv4Socket bool
	var errECNIPv4, errECNIPv6, errPIIPv4, errPIIPv6 error
	if err := sysConn.Control(func(fd uintptr) {
		localSockaddr, getsocknameErr := unix.Getsockname(int(fd))
		if getsocknameErr == nil {
			_, ipv4Socket = localSockaddr.(*unix.SockaddrInet4)
		}

		errECNIPv4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTOS, 1)
		errECNIPv6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVTCLASS, 1)

		if needsPacketInfo {
			errPIIPv4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, ipv4PKTINFO, 1)
			errPIIPv6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1)
		}
	}); err != nil {
		return nil, err
	}
	switch {
	case errECNIPv4 == nil && errECNIPv6 == nil:
		utils.DefaultLogger.Debugf("Activating reading of ECN bits for IPv4 and IPv6.")
	case errECNIPv4 == nil && errECNIPv6 != nil:
		utils.DefaultLogger.Debugf("Activating reading of ECN bits for IPv4.")
	case errECNIPv4 != nil && errECNIPv6 == nil:
		utils.DefaultLogger.Debugf("Activating reading of ECN bits for IPv6.")
	case errECNIPv4 != nil && errECNIPv6 != nil:
		return nil, errors.New("activating ECN failed for both IPv4 and IPv6")
	}
	if needsPacketInfo {
		switch {
		case errPIIPv4 == nil && errPIIPv6 == nil:
			utils.DefaultLogger.Debugf("Activating reading of packet info for IPv4 and IPv6.")
		case errPIIPv4 == nil && errPIIPv6 != nil:
			utils.DefaultLogger.Debugf("Activating reading of packet info bits for IPv4.")
		case errPIIPv4 != nil && errPIIPv6 == nil:
			utils.DefaultLogger.Debugf("Activating reading of packet info bits for IPv6.")
		case errPIIPv4 != nil && errPIIPv6 != nil:
			return nil, errors.New("activating packet info failed for both IPv4 and IPv6")
		}
	}

	// Allows callers to pass in a connection that already satisfies batchConn interface
	// to make use of the optimisation. Otherwise, ipv4.NewPacketConn would unwrap the file descriptor
	// via SyscallConn(), and read it that way, which might not be what the caller wants.
	var bc batchConn
	if ibc, ok := pc.(batchConn); ok {
		bc = ibc
	} else if mbc := newBatchReader(sysConn, false); mbc != nil {
		bc = mbc
	} else {
		bc = ipv4.NewPacketConn(&udpCompatConn{PacketConn: pc, sysConn: sysConn})
	}

	msgs := make([]ipv4.Message, batchSize)
	for i := range msgs {
		// preallocate the [][]byte
		msgs[i].Buffers = make([][]byte, 1)
	}
	gso := isGSOEnabled(sysConn)
	oobConn := &oobConn{
		PacketConn: pc,
		sysConn:    sysConn,
		batchConn:  bc,
		ipv4Socket: ipv4Socket,
		messages:   msgs,
		readPos:    batchSize,
		cap: Capabilities{
			DF:  supportsDF,
			GSO: gso,
			ECN: isECNEnabled(),
		},
	}
	if gso {
		oobConn.segmentWriter = newSegmentWriter(sysConn)
	}
	for i := range batchSize {
		oobConn.messages[i].OOB = make([]byte, oobBufferSize)
	}
	return oobConn, nil
}

func newConnectedConn(c net.Conn, sysConn syscall.RawConn, supportsDF bool) (*oobConn, error) {
	// The kernel routes every send to the connected peer and fills in the local address,
	// so packet info is never needed; only ECN reporting is enabled.
	var ipv4Socket bool
	var errECNIPv4, errECNIPv6 error
	err := sysConn.Control(func(fd uintptr) {
		localSockaddr, getsocknameErr := unix.Getsockname(int(fd))
		if getsocknameErr == nil {
			_, ipv4Socket = localSockaddr.(*unix.SockaddrInet4)
		}

		errECNIPv4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_RECVTOS, 1)
		errECNIPv6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVTCLASS, 1)
	})
	if err != nil {
		return nil, err
	}
	switch {
	case errECNIPv4 == nil && errECNIPv6 == nil:
		utils.DefaultLogger.Debugf("Activating reading of ECN bits for IPv4 and IPv6.")
	case errECNIPv4 == nil && errECNIPv6 != nil:
		utils.DefaultLogger.Debugf("Activating reading of ECN bits for IPv4.")
	case errECNIPv4 != nil && errECNIPv6 == nil:
		utils.DefaultLogger.Debugf("Activating reading of ECN bits for IPv6.")
	case errECNIPv4 != nil && errECNIPv6 != nil:
		return nil, errors.New("activating ECN failed for both IPv4 and IPv6")
	}

	packetConn := &connectedCompatConn{Conn: c, sysConn: sysConn}
	var bc batchConn
	if ibc, ok := c.(batchConn); ok {
		bc = ibc
	} else if mbc := newBatchReader(sysConn, true); mbc != nil {
		bc = mbc
	} else {
		bc = ipv4.NewPacketConn(packetConn)
	}

	msgs := make([]ipv4.Message, batchSize)
	for i := range msgs {
		// preallocate the [][]byte
		msgs[i].Buffers = make([][]byte, 1)
	}
	gso := isGSOEnabled(sysConn)
	oobConn := &oobConn{
		PacketConn:     packetConn,
		sysConn:        sysConn,
		batchConn:      bc,
		ipv4Socket:     ipv4Socket,
		remoteAddr:     c.RemoteAddr(),
		remoteAddrPort: normalizedAddrPort(c.RemoteAddr()),
		messages:       msgs,
		readPos:        batchSize,
		cap: Capabilities{
			DF:  supportsDF,
			GSO: gso,
			ECN: isECNEnabled(),
		},
	}
	if gso {
		oobConn.segmentWriter = newSegmentWriter(sysConn)
	}
	for i := range batchSize {
		oobConn.messages[i].OOB = make([]byte, oobBufferSize)
	}
	return oobConn, nil
}

func normalizedAddrPort(addr net.Addr) netip.AddrPort {
	addrPortAddr, isAddrPortAddr := addr.(interface{ AddrPort() netip.AddrPort })
	if !isAddrPortAddr {
		return netip.AddrPort{}
	}
	addrPort := addrPortAddr.AddrPort()
	return netip.AddrPortFrom(addrPort.Addr().Unmap(), addrPort.Port())
}

var invalidCmsgOnceV4, invalidCmsgOnceV6 sync.Once

func (c *oobConn) ReadPacket() (Packet, error) {
	if len(c.messages) == int(c.readPos) { // all messages read. Read the next batch of messages.
		c.messages = c.messages[:batchSize]
		// replace buffers data buffers up to the packet that has been consumed during the last ReadBatch call
		for i := uint8(0); i < c.readPos; i++ {
			buffer := GetPacketBuffer()
			buffer.Data = buffer.Data[:protocol.MaxReceivePacketSize]
			c.buffers[i] = buffer
			c.messages[i].Buffers[0] = c.buffers[i].Data
		}
		c.readPos = 0

		n, err := c.batchConn.ReadBatch(c.messages, 0)
		if n == 0 || err != nil {
			return Packet{}, err
		}
		c.messages = c.messages[:n]
	}

	msg := c.messages[c.readPos]
	buffer := c.buffers[c.readPos]
	c.readPos++

	remoteAddr := msg.Addr
	if c.remoteAddr != nil {
		remoteAddr = c.remoteAddr
	}
	data := msg.OOB[:msg.NN]
	p := Packet{
		RemoteAddr: remoteAddr,
		RcvTime:    monotime.Now(),
		Data:       msg.Buffers[0][:msg.N],
		Buffer:     buffer,
	}
	for len(data) > 0 {
		hdr, body, remainder, err := unix.ParseOneSocketControlMessage(data)
		if err != nil {
			return Packet{}, err
		}
		if hdr.Level == unix.IPPROTO_IP {
			switch hdr.Type {
			case msgTypeIPTOS:
				if len(body) != 1 {
					return Packet{}, errors.New("invalid IPTOS size")
				}
				p.ECN = protocol.ParseECNHeaderBits(body[0] & ecnMask)
			case ipv4PKTINFO:
				ip, ifIndex, ok := parseIPv4PktInfo(body)
				if ok {
					p.Info.Addr = ip
					p.Info.IfIndex = ifIndex
				} else {
					invalidCmsgOnceV4.Do(func() {
						log.Printf("Received invalid IPv4 packet info control message: %+x. "+
							"This should never occur, please open a new issue and include details about the architecture.", body)
					})
				}
			}
		}
		if hdr.Level == unix.IPPROTO_IPV6 {
			switch hdr.Type {
			case unix.IPV6_TCLASS:
				if len(body) != 4 {
					return Packet{}, errors.New("invalid IPV6_TCLASS size")
				}
				bits := uint8(binary.NativeEndian.Uint32(body)) & ecnMask
				p.ECN = protocol.ParseECNHeaderBits(bits)
			case unix.IPV6_PKTINFO:
				// struct in6_pktinfo {
				// 	struct in6_addr ipi6_addr;    /* src/dst IPv6 address */
				// 	unsigned int    ipi6_ifindex; /* send/recv interface index */
				// };
				if len(body) == 20 {
					p.Info.Addr = netip.AddrFrom16(*(*[16]byte)(body[:16])).Unmap()
					p.Info.IfIndex = binary.NativeEndian.Uint32(body[16:])
				} else {
					invalidCmsgOnceV6.Do(func() {
						log.Printf("Received invalid IPv6 packet info control message: %+x. "+
							"This should never occur, please open a new issue and include details about the architecture.", body)
					})
				}
			}
		}
		data = remainder
	}
	return p, nil
}

// WritePacket writes a new packet.
func (c *oobConn) WritePacket(b []byte, addr net.Addr, packetInfoOOB []byte, gsoSize uint16, ecn protocol.ECN) (int, error) {
	var sockaddr unix.Sockaddr
	var remoteIsIPv4 bool
	if c.remoteAddr == nil {
		sockaddr, remoteIsIPv4 = c.sockaddrOf(addr)
		if sockaddr == nil {
			return 0, fmt.Errorf("cannot send to %s (%T): unsupported address type or family", addr, addr)
		}
	} else {
		if addr != c.remoteAddr && normalizedAddrPort(addr) != c.remoteAddrPort {
			return 0, fmt.Errorf("cannot send to %s on a conn connected to %s", addr, c.remoteAddr)
		}
		remoteIsIPv4 = c.ipv4Socket || c.remoteAddrPort.Addr().Is4()
	}
	oob := packetInfoOOB
	var segmentSize int
	if gsoSize > 0 {
		if !c.Capabilities().GSO {
			panic("GSO disabled")
		}
		// Only request UDP GSO when the payload will actually be segmented.
		// Some drivers/devices misbehave when UDP_SEGMENT is set for an effectively
		// single-segment send (segment_size >= payload length). This mirrors quinn-udp's
		// behavior.
		if len(b) > int(gsoSize) {
			segmentSize = int(gsoSize)
			if c.segmentWriter == nil {
				oob = appendUDPSegmentSizeMsg(oob, gsoSize)
			}
		}
	}
	if ecn != protocol.ECNUnsupported {
		if !c.Capabilities().ECN {
			panic("tried to send an ECN-marked packet although ECN is disabled")
		}
		if remoteIsIPv4 {
			oob = appendIPv4ECNMsg(oob, ecn)
		} else {
			oob = appendIPv6ECNMsg(oob, ecn)
		}
	}
	if segmentSize > 0 && c.segmentWriter != nil {
		return c.segmentWriter.WriteSegments(b, segmentSize, sockaddr, oob)
	}
	var n int
	var sendErr error
	err := c.sysConn.Write(func(fd uintptr) bool {
		for {
			n, sendErr = unix.SendmsgN(int(fd), b, oob, sockaddr, 0)
			if sendErr == unix.EINTR {
				continue
			}
			return sendErr != unix.EAGAIN
		}
	})
	if err != nil {
		return n, err
	}
	if sendErr != nil {
		return n, os.NewSyscallError("sendmsg", sendErr)
	}
	return n, nil
}

func (c *oobConn) sockaddrOf(addr net.Addr) (_ unix.Sockaddr, ipv4 bool) {
	udpAddr, isUDPAddr := addr.(*net.UDPAddr)
	if isUDPAddr {
		cached := c.writeSockaddrCache.Load()
		if cached != nil && cached.addr == udpAddr {
			return cached.sockaddr, cached.ipv4
		}
	}
	addrPort := normalizedAddrPort(addr)
	if !addrPort.IsValid() {
		return nil, false
	}
	ip := addrPort.Addr()
	var sockaddr unix.Sockaddr
	if c.ipv4Socket {
		if !ip.Is4() {
			return nil, false
		}
		sockaddr = &unix.SockaddrInet4{Port: int(addrPort.Port()), Addr: ip.As4()}
	} else {
		sockaddr = &unix.SockaddrInet6{Port: int(addrPort.Port()), Addr: ip.As16(), ZoneId: zoneIndex(ip.Zone())}
	}
	if isUDPAddr {
		c.writeSockaddrCache.Store(&writeSockaddrEntry{addr: udpAddr, sockaddr: sockaddr, ipv4: ip.Is4()})
	}
	return sockaddr, ip.Is4()
}

func zoneIndex(zone string) uint32 {
	if zone == "" {
		return 0
	}
	iface, err := net.InterfaceByName(zone)
	if err == nil {
		return uint32(iface.Index)
	}
	index, err := strconv.Atoi(zone)
	if err == nil {
		return uint32(index)
	}
	return 0
}

func (c *oobConn) Capabilities() Capabilities {
	return c.cap
}

type PacketInfo struct {
	Addr    netip.Addr
	IfIndex uint32
}

func (info *PacketInfo) OOB() []byte {
	if info == nil {
		return nil
	}
	if info.Addr.Is4() {
		return marshalIPv4PktInfo(info.Addr.As4(), info.IfIndex)
	} else if info.Addr.Is6() {
		ip := info.Addr.As16()
		// struct in6_pktinfo {
		// 	struct in6_addr ipi6_addr;    /* src/dst IPv6 address */
		// 	unsigned int    ipi6_ifindex; /* send/recv interface index */
		// };
		cm := ipv6.ControlMessage{
			Src:     ip[:],
			IfIndex: int(info.IfIndex),
		}
		return cm.Marshal()
	}
	return nil
}

func appendIPv4ECNMsg(b []byte, val protocol.ECN) []byte {
	startLen := len(b)
	b = append(b, make([]byte, unix.CmsgSpace(ecnIPv4DataLen))...)
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[startLen]))
	h.Level = syscall.IPPROTO_IP
	h.Type = unix.IP_TOS
	h.SetLen(unix.CmsgLen(ecnIPv4DataLen))

	// UnixRights uses the private `data` method, but I *think* this achieves the same goal.
	offset := startLen + unix.CmsgSpace(0)
	b[offset] = val.ToHeaderBits()
	return b
}

func appendIPv6ECNMsg(b []byte, val protocol.ECN) []byte {
	startLen := len(b)
	const dataLen = 4
	b = append(b, make([]byte, unix.CmsgSpace(dataLen))...)
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[startLen]))
	h.Level = syscall.IPPROTO_IPV6
	h.Type = unix.IPV6_TCLASS
	h.SetLen(unix.CmsgLen(dataLen))

	// UnixRights uses the private `data` method, but I *think* this achieves the same goal.
	offset := startLen + unix.CmsgSpace(0)
	binary.NativeEndian.PutUint32(b[offset:offset+dataLen], uint32(val.ToHeaderBits()))
	return b
}
