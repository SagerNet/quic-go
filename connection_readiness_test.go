package quic

import (
	"context"
	"fmt"
	"testing"
	"time"

	ext "github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/internal/ackhandler"
	"github.com/sagernet/quic-go/internal/handshake"
	"github.com/sagernet/quic-go/internal/monotime"
	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/internal/utils"
	"github.com/sagernet/quic-go/internal/wire"
	publicmono "github.com/sagernet/quic-go/monotime"
)

// Substitutions: recording congestion policy, inert cryptographic sealer,
// deterministic ACK supplier and socket-free connection capability stub.
// No packet reaches a socket: the real writer queue is drained without Run.
// Real stream, flow controllers, framer, packer, handler and Conn scheduler run.
type backlogSealer struct{}

func (backlogSealer) Seal(dst, src []byte, _ protocol.PacketNumber, _ []byte) []byte {
	dst = append(dst, src...)
	return append(dst, make([]byte, 16)...)
}
func (backlogSealer) EncryptHeader([]byte, *byte, []byte) {}
func (backlogSealer) Overhead() int                       { return 16 }
func (backlogSealer) KeyPhase() protocol.KeyPhaseBit      { return protocol.KeyPhaseZero }

type backlogCrypto struct{ sealingManager }

func (backlogCrypto) Get1RTTSealer() (handshake.ShortHeaderSealer, error) {
	return backlogSealer{}, nil
}

type backlogSendConn struct {
	sendConn
	gso bool
}

func (c backlogSendConn) capabilities() connCapabilities { return connCapabilities{GSO: c.gso} }

type backlogACK struct{ enabled bool }

func (a *backlogACK) GetAckFrame(_ protocol.EncryptionLevel, _ monotime.Time, _ bool) *wire.AckFrame {
	if !a.enabled {
		return nil
	}
	a.enabled = false
	return &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}}
}

type backlogCC struct {
	ext.CongestionControlEx
	pacing        bool
	until         publicmono.Time
	notifications int
	ackEliciting  []bool
}

func (c *backlogCC) SetRTTStatsProvider(ext.RTTStatsProvider)    {}
func (c *backlogCC) CanSend(ext.ByteCount) bool                  { return true }
func (c *backlogCC) HasPacingBudget(publicmono.Time) bool        { return c.pacing }
func (c *backlogCC) TimeUntilSend(ext.ByteCount) publicmono.Time { return c.until }
func (c *backlogCC) OnAppLimited(ext.ByteCount)                  { c.notifications++ }
func (c *backlogCC) OnPacketSent(_ publicmono.Time, _ ext.ByteCount, _ ext.PacketNumber, _ ext.ByteCount, ack bool) {
	c.ackEliciting = append(c.ackEliciting, ack)
	if ack {
		c.pacing = false
	}
}
func (c *backlogCC) GetCongestionWindow() ext.ByteCount { return 1000000 }
func (c *backlogCC) InSlowStart() bool                  { return true }
func (c *backlogCC) InRecovery() bool                   { return false }

type backlogPacker struct {
	*packetPacker
	sent []shortHeaderPacket
}

func (p *backlogPacker) AppendPacket(b *packetBuffer, n protocol.ByteCount, now monotime.Time, v protocol.Version) (shortHeaderPacket, error) {
	packet, err := p.packetPacker.AppendPacket(b, n, now, v)
	if err == nil {
		p.sent = append(p.sent, packet)
	}
	return packet, err
}
func (p *backlogPacker) PackAckOnlyPacket(n protocol.ByteCount, now monotime.Time, v protocol.Version) (shortHeaderPacket, *packetBuffer, error) {
	packet, b, err := p.packetPacker.PackAckOnlyPacket(n, now, v)
	if err == nil {
		p.sent = append(p.sent, packet)
	} else {
		b.Release()
	}
	return packet, b, err
}

func newBacklogConn(t *testing.T) (*Conn, *SendStream, *backlogCC, *backlogACK, *backlogPacker) {
	t.Helper()
	readiness := new(ackhandler.AppLimitedReadiness)
	logger := utils.DefaultLogger.WithPrefix("paced-backlog-unit")
	logger.SetLogLevel(utils.LogLevelNothing)
	rtt := utils.NewRTTStats()
	fc := newConnectionFlowController(1<<20, 1<<20, func(protocol.ByteCount) bool { return true }, rtt, logger)
	fc.appLimitedReadiness = readiness
	fc.UpdateSendWindow(1 << 20)
	h := ackhandler.NewSentPacketHandler(0, 1200, rtt, &utils.ConnectionStats{}, true, false, func(protocol.PacketNumber) {}, protocol.PerspectiveClient, false, nil, logger, readiness)
	cc := &backlogCC{pacing: true}
	h.SetCongestionControl(cc)
	q := newSendQueue(nil).(*sendQueue)
	f := newFramer(fc, readiness)
	cid := protocol.ParseConnectionID([]byte("fixture1"))
	c := &Conn{appLimitedReadiness: readiness, sentPacketHandler: h, sendQueue: q, framer: f, connFlowController: fc, conn: backlogSendConn{}, cryptoStreamManager: &cryptoStreamManager{oneRTTStream: &cryptoStream{}}, connIDManager: newConnIDManager(cid, func(protocol.StatelessResetToken) {}, func(protocol.StatelessResetToken) {}, func(wire.Frame) {}), config: &Config{InitialPacketSize: 1200}, perspective: protocol.PerspectiveClient, handshakeConfirmed: true, version: protocol.Version1, logger: logger, sendingScheduled: make(chan struct{}, 1)}
	c.retransmissionQueue = newRetransmissionQueue(readiness)
	c.datagramQueue = newDatagramQueue(c.scheduleSending, logger, readiness)
	a := &backlogACK{}
	p := &backlogPacker{packetPacker: newPacketPacker(cid, func() protocol.ConnectionID { return cid }, nil, nil, h, c.retransmissionQueue, backlogCrypto{}, f, a, c.datagramQueue, protocol.PerspectiveClient, false)}
	c.packer = p
	sf := newStreamFlowController(0, fc, 1<<20, 1<<20, 1<<20, rtt, logger)
	s := newSendStream(context.Background(), 0, c, sf, false)
	t.Cleanup(func() {
		for len(q.queue) > 0 {
			entry := <-q.queue
			entry.buf.Release()
		}
	})
	return c, s, cc, a, p
}

// The congestion policy deliberately delays queued data. This tests the
// scheduler contract independent of a particular congestion controller's pacer.
func TestSchedulerReadinessBoundsIdle(t *testing.T) {
	for _, gso := range []bool{false, true} {
		t.Run(fmt.Sprintf("GSO=%v", gso), func(t *testing.T) { checkPacedBacklog(t, gso) })
	}
}

func checkPacedBacklog(t *testing.T, gso bool) {
	for _, api := range []string{"Write", "TryWriteAll"} {
		for _, idle := range []time.Duration{0, 3 * time.Millisecond} {
			for _, withACK := range []bool{false, true} {
				name := api + "/" + idle.String() + "/" + map[bool]string{false: "no-ack", true: "ack-only"}[withACK]
				t.Run(name, func(t *testing.T) {
					c, s, cc, a, p := newBacklogConn(t)
					c.conn = backlogSendConn{gso: gso}
					start := monotime.Now()
					if err := c.triggerSending(start); err != nil {
						t.Fatal(err)
					}
					if len(p.sent) != 0 || c.framer.HasData() {
						t.Fatal("initial packer was not empty")
					}
					if idle > 0 {
						time.Sleep(idle)
					}
					data := []byte("application-data")
					if api == "Write" {
						n, err := s.Write(data)
						if err != nil || n != len(data) {
							t.Fatalf("Write=%d,%v", n, err)
						}
					} else if err := s.TryWriteAll(data); err != nil {
						t.Fatal(err)
					}
					ready := monotime.Now()
					idleUpperBound := ready.Sub(start)
					if idle == 0 && idleUpperBound >= 2*time.Millisecond {
						t.Skipf("scheduler delay invalidated the short-idle sample: publication took %v", idleUpperBound)
					}
					if idle > 0 && idleUpperBound < 3*time.Millisecond {
						t.Fatal("genuine idle control did not wait")
					}
					if !c.framer.HasData() || len(c.sendingScheduled) != 1 {
						t.Fatal("real Write did not schedule queued data")
					}
					resumed := ready.Add(6 * time.Millisecond)
					cc.pacing = false
					cc.until = publicmono.Time(resumed)
					a.enabled = withACK
					if c.sentPacketHandler.SendMode(ready.Add(time.Millisecond)) != ackhandler.SendPacingLimited {
						t.Fatal("not pacing-limited")
					}
					if err := c.triggerSending(ready.Add(time.Millisecond)); err != nil {
						t.Fatal(err)
					}
					if !c.framer.HasData() || c.pacingDeadline != resumed {
						t.Fatal("paced scheduler lost backlog or deadline")
					}
					if withACK && (len(p.sent) != 1 || p.sent[0].Ack == nil || len(p.sent[0].StreamFrames) != 0 || len(p.sent[0].Frames) != 0) {
						t.Fatal("paced scheduler did not emit pure ACK")
					}
					if !withACK && len(p.sent) != 0 {
						t.Fatal("unexpected paced packet")
					}
					beforeResume := cc.notifications
					cc.pacing = true
					if err := c.triggerSending(resumed); err != nil {
						t.Fatal(err)
					}
					last := p.sent[len(p.sent)-1]
					if len(last.StreamFrames) != 1 || string(last.StreamFrames[0].Frame.Data) != string(data) {
						t.Fatal("real queued STREAM not sent on unpace")
					}
					if !cc.ackEliciting[len(cc.ackEliciting)-1] || (withACK && cc.ackEliciting[0]) {
						t.Fatal("actual ACK/STREAM classification incorrect")
					}
					t.Logf("ready_after=%v paced_backlog=6ms ack=%v notifications_before_resume=%d total=%d", idleUpperBound, withACK, beforeResume, cc.notifications)
					want := 0
					if idle > 0 {
						want = 1
					}
					if cc.notifications != want {
						t.Fatalf("idle classification: got%d want%d", cc.notifications, want)
					}
					wantBefore := 0
					if beforeResume != wantBefore {
						t.Fatalf("unexpected notification timing: got%d want%d", beforeResume, wantBefore)
					}
				})
			}
		}
	}
}

// A stream has published bytes but has not yet made its ID visible to the
// framer. Empty observations in this interval must not start a new idle epoch.
type pausedReadinessSender struct {
	streamSender
	published chan struct{}
	activate  chan struct{}
}

func (s *pausedReadinessSender) onHasStreamData(id protocol.StreamID, str *SendStream) {
	close(s.published)
	<-s.activate
	s.streamSender.onHasStreamData(id, str)
}
func TestReadinessPublicationBeforeActivation(t *testing.T) {
	for _, api := range []string{"Write", "TryWriteAll", "FIN"} {
		t.Run(api, func(t *testing.T) {
			c, stream, cc, _, p := newBacklogConn(t)
			sender := &pausedReadinessSender{streamSender: c, published: make(chan struct{}), activate: make(chan struct{})}
			stream.sender = sender
			done := make(chan error, 1)
			go func() {
				var err error
				switch api {
				case "Write":
					_, err = stream.Write([]byte("queued"))
				case "TryWriteAll":
					err = stream.TryWriteAll([]byte("queued"))
				case "FIN":
					err = stream.Close()
				}
				done <- err
			}()
			<-sender.published
			if c.framer.HasData() {
				t.Fatal("activation was not paused")
			}
			if err := c.triggerSending(monotime.Now()); err != nil {
				t.Fatal(err)
			}
			time.Sleep(3 * time.Millisecond)
			if err := c.triggerSending(monotime.Now()); err != nil {
				t.Fatal(err)
			}
			close(sender.activate)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if err := c.triggerSending(monotime.Now()); err != nil {
				t.Fatal(err)
			}
			if len(p.sent) != 1 || len(p.sent[0].StreamFrames) != 1 {
				t.Fatal("published frame did not reach real packet")
			}
			if cc.notifications != 0 {
				t.Fatalf("source-to-activation delay counted as idle: %d", cc.notifications)
			}
		})
	}
}

type publishAfterEmptyPacker struct {
	*backlogPacker
	publish func()
}

func (p *publishAfterEmptyPacker) AppendPacket(b *packetBuffer, n protocol.ByteCount, now monotime.Time, v protocol.Version) (shortHeaderPacket, error) {
	packet, err := p.backlogPacker.AppendPacket(b, n, now, v)
	if err == errNothingToPack && p.publish != nil {
		f := p.publish
		p.publish = nil
		f()
	}
	return packet, err
}
func TestReadinessPublicationDuringEmptyProbe(t *testing.T) {
	c, stream, cc, _, p := newBacklogConn(t)
	c.packer = &publishAfterEmptyPacker{backlogPacker: p, publish: func() {
		if err := stream.TryWriteAll([]byte("during-probe")); err != nil {
			t.Fatal(err)
		}
	}}
	if err := c.triggerSending(monotime.Now()); err != nil {
		t.Fatal(err)
	}
	if !c.framer.HasData() {
		t.Fatal("fixture did not publish during empty probe")
	}
	time.Sleep(3 * time.Millisecond)
	if err := c.triggerSending(monotime.Now()); err != nil {
		t.Fatal(err)
	}
	if cc.notifications != 0 {
		t.Fatalf("completed overlapping publication accepted as empty: %d", cc.notifications)
	}
}

func TestReadinessFlowControlBlockedInterval(t *testing.T) {
	for _, scope := range []string{"stream", "connection"} {
		t.Run(scope, func(t *testing.T) {
			c, s, cc, _, p := newBacklogConn(t)
			if scope == "stream" {
				s.flowController.sendWindow = 0
			} else {
				c.connFlowController.sendWindow = 0
			}
			if _, err := s.Write([]byte("flow-blocked")); err != nil {
				t.Fatal(err)
			}
			// First materialize DATA_BLOCKED / STREAM_DATA_BLOCKED. Then probe
			// the still-active but unsendable STREAM with no controls pending.
			if err := c.triggerSending(monotime.Now()); err != nil {
				t.Fatal(err)
			}
			cc.pacing = true
			if err := c.triggerSending(monotime.Now()); err != nil {
				t.Fatal(err)
			}
			for _, packet := range p.sent {
				if len(packet.StreamFrames) > 0 {
					t.Fatal("sent without flow-control credit")
				}
			}
			if !c.framer.HasData() || c.framer.HasQueuedControlFrames() {
				t.Fatal("fixture must retain only flow-blocked STREAM")
			}
			time.Sleep(3 * time.Millisecond)
			if scope == "stream" {
				s.updateSendWindow(1000)
			} else {
				c.framer.UpdateConnectionSendWindow(1000)
			}
			if err := c.triggerSending(monotime.Now()); err != nil {
				t.Fatal(err)
			}
			if len(p.sent[len(p.sent)-1].StreamFrames) != 1 || cc.notifications != 1 {
				t.Fatalf("flow-blocked interval not preserved: notifications=%d", cc.notifications)
			}
		})
	}
}

func TestReadinessUnpackableControlBacklog(t *testing.T) {
	for _, source := range []string{"framer", "retransmission"} {
		t.Run(source, func(t *testing.T) {
			c, s, cc, _, _ := newBacklogConn(t)
			frame := &wire.NewTokenFrame{Token: make([]byte, 3000)}
			if source == "framer" {
				c.framer.QueueControlFrame(frame)
			} else {
				c.retransmissionQueue.addAppData(frame)
			}
			if err := c.triggerSending(monotime.Now()); err != nil {
				t.Fatal(err)
			}
			time.Sleep(3 * time.Millisecond)
			if source == "framer" {
				c.framer.controlFrames = nil
			} else {
				c.retransmissionQueue.appData.other = nil
			}
			if err := s.TryWriteAll([]byte("after-backlog")); err != nil {
				t.Fatal(err)
			}
			if err := c.triggerSending(monotime.Now()); err != nil {
				t.Fatal(err)
			}
			if cc.notifications != 0 {
				t.Fatal("unpackable control backlog counted as application idle")
			}
		})
	}
}

func TestReadinessOverlappingStreamPublishers(t *testing.T) {
	c, first, cc, _, _ := newBacklogConn(t)
	second := newSendStream(context.Background(), 4, c, newStreamFlowController(4, c.connFlowController, 1<<20, 1<<20, 1<<20, utils.NewRTTStats(), c.logger), false)
	streams := []*SendStream{first, second}
	senders := make([]*pausedReadinessSender, 2)
	done := make([]chan error, 2)
	for i, s := range streams {
		senders[i] = &pausedReadinessSender{streamSender: c, published: make(chan struct{}), activate: make(chan struct{})}
		s.sender = senders[i]
		done[i] = make(chan error, 1)
		go func(i int, s *SendStream) { done[i] <- s.TryWriteAll([]byte("overlap")) }(i, s)
	}
	for _, sender := range senders {
		<-sender.published
	}
	if err := c.triggerSending(monotime.Now()); err != nil {
		t.Fatal(err)
	}
	close(senders[0].activate)
	if err := <-done[0]; err != nil {
		t.Fatal(err)
	}
	if err := c.triggerSending(monotime.Now()); err != nil {
		t.Fatal(err)
	}
	cc.pacing = true
	if err := c.triggerSending(monotime.Now()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Millisecond)
	close(senders[1].activate)
	if err := <-done[1]; err != nil {
		t.Fatal(err)
	}
	if err := c.triggerSending(monotime.Now()); err != nil {
		t.Fatal(err)
	}
	if cc.notifications != 0 {
		t.Fatal("first publisher completion hid second pending activation")
	}
}

func TestReadinessPublicationOnAlreadyActiveStream(t *testing.T) {
	c, s, cc, _, p := newBacklogConn(t)
	if err := s.TryWriteAll([]byte("first-")); err != nil {
		t.Fatal(err)
	}
	paused := &pausedReadinessSender{streamSender: c, published: make(chan struct{}), activate: make(chan struct{})}
	s.sender = paused
	done := make(chan error, 1)
	go func() { done <- s.TryWriteAll([]byte("second")) }()
	<-paused.published
	if err := c.triggerSending(monotime.Now()); err != nil {
		t.Fatal(err)
	}
	if len(p.sent) != 1 || string(p.sent[0].StreamFrames[0].Frame.Data) != "first-second" {
		t.Fatal("already-active stream did not expose new source data")
	}
	cc.pacing = true
	if err := c.triggerSending(monotime.Now()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Millisecond)
	close(paused.activate)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// Completing the delayed activation must not expose an epoch accumulated
	// while this publisher was still active, even though its bytes were sent.
	start := monotime.Now()
	if err := c.triggerSending(monotime.Now()); err != nil {
		t.Fatal(err)
	}
	s.sender = c
	if err := s.TryWriteAll([]byte("third")); err != nil {
		t.Fatal(err)
	}
	if elapsed := monotime.Now().Sub(start); elapsed >= 2*time.Millisecond {
		t.Skipf("scheduler delay invalidated the final short-idle sample: %v", elapsed)
	}
	if err := c.triggerSending(monotime.Now()); err != nil {
		t.Fatal(err)
	}
	if cc.notifications != 0 {
		t.Fatal("delayed activation on active stream created false idle evidence")
	}
}
