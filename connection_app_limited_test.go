package quic

import (
	"testing"
	"time"

	ext "github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/internal/ackhandler"
	"github.com/sagernet/quic-go/internal/monotime"
	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/internal/utils"
	"github.com/sagernet/quic-go/internal/wire"
	publicmono "github.com/sagernet/quic-go/monotime"
)

type backpressureController struct {
	ext.CongestionControlEx
	notifications int
}

func (c *backpressureController) SetRTTStatsProvider(ext.RTTStatsProvider) {}
func (c *backpressureController) CanSend(ext.ByteCount) bool               { return true }
func (c *backpressureController) OnAppLimited(ext.ByteCount)               { c.notifications++ }
func (c *backpressureController) OnPacketSent(publicmono.Time, ext.ByteCount, ext.PacketNumber, ext.ByteCount, bool) {
}
func (c *backpressureController) GetCongestionWindow() ext.ByteCount { return 1000000 }
func (c *backpressureController) InSlowStart() bool                  { return true }
func (c *backpressureController) InRecovery() bool                   { return false }
func TestSendQueueBackpressureInvalidatesAppLimited(t *testing.T) {
	logger := utils.DefaultLogger.WithPrefix("writer-queue-unit")
	logger.SetLogLevel(utils.LogLevelNothing)
	readiness := new(ackhandler.AppLimitedReadiness)
	h := ackhandler.NewSentPacketHandler(0, 1200, utils.NewRTTStats(), &utils.ConnectionStats{}, true, false, func(protocol.PacketNumber) {}, protocol.PerspectiveClient, false, nil, logger, readiness)
	cc := &backpressureController{}
	h.SetCongestionControl(cc)
	q := newSendQueue(nil).(*sendQueue)
	c := &Conn{sentPacketHandler: h, sendQueue: q, appLimitedReadiness: readiness}

	// Exercise the real bounded sendQueue without starting its writer or a socket.
	base := monotime.Now()
	h.MaybeNotifyAppLimited(readiness.BeginProbe())
	for i := 0; i < sendQueueCapacity; i++ {
		q.Send(getPacketBuffer(), 0, protocol.ECNNon)
	}
	if !q.WouldBlock() || !c.sendQueueWouldBlock() {
		t.Fatal("actual full queue not recognized")
	}
	for len(q.queue) > 0 {
		e := <-q.queue
		e.buf.Release()
	}
	h.SentPacket(base.Add(5*time.Millisecond), 0, protocol.InvalidPacketNumber, nil, []ackhandler.Frame{{Frame: &wire.PingFrame{}}}, protocol.Encryption1RTT, protocol.ECNNon, 100, false, false)
	if cc.notifications != 0 {
		t.Fatal("writer-blocked interval leaked into application-limited notification")
	}
	// An available writer must not erase a genuinely empty observation.
	h.MaybeNotifyAppLimited(readiness.BeginProbe())
	base = monotime.Now()
	if c.sendQueueWouldBlock() {
		t.Fatal("empty queue reported blocked")
	}
	h.SentPacket(base.Add(5*time.Millisecond), 1, protocol.InvalidPacketNumber, nil, []ackhandler.Frame{{Frame: &wire.PingFrame{}}}, protocol.Encryption1RTT, protocol.ECNNon, 100, false, false)
	if cc.notifications != 1 {
		t.Fatal("available writer lost a valid empty observation")
	}
}
