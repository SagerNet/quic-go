package ackhandler

import (
	"fmt"
	"testing"
	"time"

	ext "github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/internal/monotime"
	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/internal/utils"
	"github.com/sagernet/quic-go/internal/wire"
	publicmono "github.com/sagernet/quic-go/monotime"
)

// The recording controller observes calls from the real handler and history.
type appLimitedController struct {
	ext.CongestionControlEx
	canSend         bool
	notifications   int
	sent            []bool
	events          []string
	limitedInFlight []ext.ByteCount
	sentInFlight    []ext.ByteCount
	pacing          bool
	nextCanSend     *bool
}

func (c *appLimitedController) HasPacingBudget(publicmono.Time) bool { return !c.pacing }
func (c *appLimitedController) MaybeExitSlowStart()                  {}
func (c *appLimitedController) OnPacketAcked(ext.PacketNumber, ext.ByteCount, ext.ByteCount, publicmono.Time) {
}
func (c *appLimitedController) OnCongestionEvent(ext.PacketNumber, ext.ByteCount, ext.ByteCount) {}
func (c *appLimitedController) OnPacketsLost(ext.PacketNumber)                                   {}
func (c *appLimitedController) OnPacketNeutered(ext.PacketNumber)                                {}
func (c *appLimitedController) OnCongestionEventEx(_ ext.ByteCount, _ publicmono.Time, _ []ext.AckedPacketInfo, _ []ext.LostPacketInfo) {
	if c.nextCanSend != nil {
		c.canSend = *c.nextCanSend
	}
}
func (c *appLimitedController) SetRTTStatsProvider(ext.RTTStatsProvider) {}
func (c *appLimitedController) CanSend(ext.ByteCount) bool               { return c.canSend }
func (c *appLimitedController) OnAppLimited(inFlight ext.ByteCount) {
	c.notifications++
	c.events = append(c.events, "limited")
	c.limitedInFlight = append(c.limitedInFlight, inFlight)
}
func (c *appLimitedController) OnPacketSent(_ publicmono.Time, inFlight ext.ByteCount, _ ext.PacketNumber, _ ext.ByteCount, ackEliciting bool) {
	c.sent = append(c.sent, ackEliciting)
	c.events = append(c.events, "sent")
	c.sentInFlight = append(c.sentInFlight, inFlight)
}
func (c *appLimitedController) GetCongestionWindow() ext.ByteCount { return 1000000 }
func (c *appLimitedController) InSlowStart() bool                  { return true }
func (c *appLimitedController) InRecovery() bool                   { return false }
func newAppLimitedHandler() (*sentPacketHandler, *appLimitedController) {
	logger := utils.DefaultLogger.WithPrefix("isolated-handler-test")
	logger.SetLogLevel(utils.LogLevelNothing)
	h := NewSentPacketHandler(0, 1200, utils.NewRTTStats(), &utils.ConnectionStats{}, true, false, func(protocol.PacketNumber) {}, protocol.PerspectiveClient, false, nil, logger, new(AppLimitedReadiness)).(*sentPacketHandler)
	h.peerCompletedAddressValidation = true
	c := &appLimitedController{canSend: true}
	h.SetCongestionControl(c)
	return h, c
}

// MaybeNotifyAppLimited uses the process clock. For deterministic sequences we
// inject only its already-observed timestamp state, with the identical rule
// "set if zero". No production branch, packet flag or notification is mocked.
func recordEmptyAt(h *sentPacketHandler, at monotime.Time) {
	if h.appLimitedReadiness.observation(monotime.Now()).start.IsZero() {
		h.MaybeNotifyAppLimited(h.appLimitedReadiness.BeginProbe())
		if !h.appLimitedReadiness.observation(monotime.Now()).start.IsZero() {
			h.appLimitedReadiness.start = at
		}
	}
}
func sendTestPacket(h *sentPacketHandler, at monotime.Time, pn int, kind string) {
	var streams []StreamFrame
	var frames []Frame
	var mtu, path bool
	switch kind {
	case "ack-only":
	case "stream", "requeued-stream":
		streams = []StreamFrame{{Frame: &wire.StreamFrame{StreamID: 4, Data: []byte("synthetic")}}}
	case "ping":
		frames = []Frame{{Frame: &wire.PingFrame{}}}
	case "max-data":
		frames = []Frame{{Frame: &wire.MaxDataFrame{MaximumData: 1 << 20}}}
	case "mtu-probe":
		frames = []Frame{{Frame: &wire.PingFrame{}}}
		mtu = true
	case "path-probe":
		frames = []Frame{{Frame: &wire.PathChallengeFrame{}}}
		path = true
	default:
		panic(kind)
	}
	h.SentPacket(at, protocol.PacketNumber(pn), protocol.InvalidPacketNumber, streams, frames, protocol.Encryption1RTT, protocol.ECNNon, 100, mtu, path)
}
func TestAppLimitedEmptyNotificationPreservesFirstTimestamp(t *testing.T) {
	h, _ := newAppLimitedHandler()
	if !h.appLimitedReadiness.observation(monotime.Now()).start.IsZero() {
		t.Fatal("unexpected initial mark")
	}
	h.MaybeNotifyAppLimited(h.appLimitedReadiness.BeginProbe())
	first := h.appLimitedReadiness.observation(monotime.Now()).start
	if first.IsZero() {
		t.Fatal("no timestamp")
	}
	h.MaybeNotifyAppLimited(h.appLimitedReadiness.BeginProbe())
	if h.appLimitedReadiness.observation(monotime.Now()).start != first {
		t.Fatal("repeated empty event moved timestamp")
	}
}
func TestAppLimitedInterleavedACKAndDataDoesNotMarkSustainedWriter(t *testing.T) {
	h, c := newAppLimitedHandler()
	base := monotime.Now()
	gap := 500 * time.Microsecond
	for i := 0; i < 20; i++ {
		at := base.Add(time.Duration(i) * 2 * gap)
		recordEmptyAt(h, at)
		sendTestPacket(h, at.Add(gap), 2*i+1, "ack-only")
		recordEmptyAt(h, at.Add(gap))
		sendTestPacket(h, at.Add(2*gap), 2*i+2, "stream")
	}
	if c.notifications != 0 {
		t.Fatalf("sustained writer falsely marked %d times", c.notifications)
	}
}
func TestAppLimitedCallbackOrderingUsesPriorInFlight(t *testing.T) {
	h, c := newAppLimitedHandler()
	base := monotime.Now()
	sendTestPacket(h, base, 1, "stream")
	recordEmptyAt(h, base)
	sendTestPacket(h, base.Add(5*time.Millisecond), 2, "stream")
	if fmt.Sprint(c.events) != "[sent limited sent]" {
		t.Fatalf("callback order %v", c.events)
	}
	if len(c.limitedInFlight) != 1 || c.limitedInFlight[0] != 100 || c.sentInFlight[1] != 100 || h.bytesInFlight != 200 {
		t.Fatalf("wrong inflight snapshots limited=%v sent=%v final=%d", c.limitedInFlight, c.sentInFlight, h.bytesInFlight)
	}
}
func TestAppLimitedNoEmptyMarker(t *testing.T) {
	h, c := newAppLimitedHandler()
	sendTestPacket(h, monotime.Now().Add(time.Hour), 1, "stream")
	if c.notifications != 0 || !h.appLimitedReadiness.observation(monotime.Now()).start.IsZero() {
		t.Fatal("unmarked send notified")
	}
}

func TestAppLimitedACKCadence(t *testing.T) {
	h, c := newAppLimitedHandler()
	base := monotime.Now()
	recordEmptyAt(h, base)
	// Classifications match the packer's 19 pure ACKs followed by ACK+PING.
	// This handler test does not substitute for a packet-packer integration test.
	for i := 1; i <= protocol.MaxNonAckElicitingAcks; i++ {
		sendTestPacket(h, base.Add(time.Duration(i)*500*time.Microsecond), i, "ack-only")
		if h.appLimitedReadiness.observation(monotime.Now()).start != base || c.notifications != 0 || c.sent[len(c.sent)-1] {
			t.Fatal("pure ACK consumed or reported the idle observation")
		}
	}
	sendTestPacket(h, base.Add(10*time.Millisecond), 20, "ping")
	if c.notifications != 1 || !h.appLimitedReadiness.observation(monotime.Now()).start.IsZero() || !c.sent[len(c.sent)-1] {
		t.Fatal("ACK+PING did not consume the eligible observation")
	}
}
func TestAppLimitedThreshold(t *testing.T) {
	for _, delay := range []time.Duration{appLimitedThreshold - time.Nanosecond, appLimitedThreshold, appLimitedThreshold + time.Nanosecond} {
		t.Run(delay.String(), func(t *testing.T) {
			h, c := newAppLimitedHandler()
			base := monotime.Now()
			recordEmptyAt(h, base)
			sendTestPacket(h, base.Add(delay), 1, "stream")
			want := 0
			if delay >= appLimitedThreshold {
				want = 1
			}
			if c.notifications != want || !h.appLimitedReadiness.observation(monotime.Now()).start.IsZero() {
				t.Fatalf("notifications=%d want%d", c.notifications, want)
			}
		})
	}
}

type basicAppLimitedController struct{ ext.CongestionControl }

func TestAppLimitedNonExtendedController(t *testing.T) {
	h, c := newAppLimitedHandler()
	h.SetCongestionControl(&basicAppLimitedController{c})
	base := monotime.Now()
	recordEmptyAt(h, base)
	sendTestPacket(h, base.Add(5*time.Millisecond), 1, "stream")
	if c.notifications != 0 || len(c.sent) != 1 || !h.appLimitedReadiness.observation(monotime.Now()).start.IsZero() {
		t.Fatal("base controller behavior changed")
	}
}

func TestAppLimitedRejectForbiddenArming(t *testing.T) {
	for _, kind := range []string{"cwnd", "pto"} {
		t.Run(kind, func(t *testing.T) {
			h, c := newAppLimitedHandler()
			if kind == "cwnd" {
				c.canSend = false
			} else {
				h.numProbesToSend = 1
			}
			h.MaybeNotifyAppLimited(h.appLimitedReadiness.BeginProbe())
			if !h.appLimitedReadiness.observation(monotime.Now()).start.IsZero() {
				t.Fatal("forbidden empty marker armed")
			}
		})
	}
}
func TestAppLimitedQuietBlockedEpoch(t *testing.T) {
	h, c := newAppLimitedHandler()
	base := monotime.Now()
	recordEmptyAt(h, base)
	c.canSend = false
	if h.SendMode(base.Add(time.Millisecond)) != SendAck {
		t.Fatal("did not exercise real blocked mode")
	}
	if !h.appLimitedReadiness.observation(monotime.Now()).start.IsZero() {
		t.Error("observed blocking retained old marker")
	}
	c.canSend = true
	recordEmptyAt(h, base.Add(5*time.Millisecond))
	sendTestPacket(h, base.Add(5500*time.Microsecond), 1, "stream")
	if c.notifications != 0 {
		t.Fatal("old blocked interval counted after fresh empty observation")
	}
}
func TestAppLimitedSilentACKPermissionTransition(t *testing.T) {
	h, c := newAppLimitedHandler()
	base := monotime.Now()
	sendTestPacket(h, base, 1, "stream")
	sendTestPacket(h, base.Add(time.Microsecond), 2, "stream")
	recordEmptyAt(h, base.Add(2*time.Microsecond))
	denied := false
	c.nextCanSend = &denied
	if _, err := h.ReceivedAck(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 1}}}, protocol.Encryption1RTT, base.Add(time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if c.canSend {
		t.Fatal("controller callback did not deny sending")
	}
	if !h.appLimitedReadiness.observation(monotime.Now()).start.IsZero() {
		t.Error("ACK callback denial retained old marker")
	}
	allowed := true
	c.nextCanSend = &allowed
	if _, err := h.ReceivedAck(&wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 2, Largest: 2}}}, protocol.Encryption1RTT, base.Add(4*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if !c.canSend {
		t.Fatal("controller callback did not restore sending")
	}
	// No SendMode call occurs anywhere in this test.
	sendTestPacket(h, base.Add(5*time.Millisecond), 3, "stream")
	if c.notifications != 0 {
		t.Fatal("silent blocked epoch leaked into notification")
	}
}
func TestAppLimitedHardLimits(t *testing.T) {
	for _, kind := range []string{"amplification", "tracked", "outstanding"} {
		t.Run(kind, func(t *testing.T) {
			h, _ := newAppLimitedHandler()
			base := monotime.Now()
			recordEmptyAt(h, base)
			want := SendNone
			switch kind {
			case "amplification":
				h.peerAddressValidated = false
				h.bytesSent = 0
				h.bytesReceived = 0
			case "tracked":
				h.appDataPackets.history.packets = make([]*packet, protocol.MaxTrackedSentPackets)
			case "outstanding":
				h.appDataPackets.history.packets = make([]*packet, protocol.MaxOutstandingSentPackets)
				want = SendAck
			}
			if got := h.SendMode(base.Add(time.Millisecond)); got != want {
				t.Fatalf("mode=%v want=%v", got, want)
			}
			if !h.appLimitedReadiness.observation(monotime.Now()).start.IsZero() {
				t.Fatal("hard limit retained empty marker")
			}
		})
	}
}
func TestAppLimitedPTOAccountingDoesNotHideBlockedEpoch(t *testing.T) {
	h, c := newAppLimitedHandler()
	h.handshakeConfirmed = true
	h.initialPackets = nil
	h.handshakePackets = nil
	base := monotime.Now()
	pn := h.PopPacketNumber(protocol.Encryption1RTT)
	sendTestPacket(h, base, int(pn), "stream")
	recordEmptyAt(h, base.Add(time.Microsecond))
	c.canSend = false
	if err := h.OnLossDetectionTimeout(base.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if h.numProbesToSend == 0 || h.SendMode(base.Add(time.Second)) != SendPTOAppData {
		t.Fatal("real PTO entry not exercised")
	}
	if !h.QueueProbePacket(protocol.Encryption1RTT) || h.bytesInFlight != 0 {
		t.Fatal("real probe accounting did not remove flight bytes")
	}
	c.canSend = true
	pn = h.PopPacketNumber(protocol.Encryption1RTT)
	sendTestPacket(h, base.Add(time.Second+time.Millisecond), int(pn), "ping")
	if c.notifications != 0 {
		t.Fatal("PTO accounted old empty interval after flight-byte removal")
	}
}
func TestAppLimitedControllerGeneration(t *testing.T) {
	h, _ := newAppLimitedHandler()
	base := monotime.Now()
	recordEmptyAt(h, base)
	b := &appLimitedController{canSend: true}
	h.SetCongestionControl(b)
	c := &appLimitedController{canSend: true}
	h.SetCongestionControl(c)
	// Two installations with no intervening send share firstPacketNumber, so
	// firstPacketNumber alone cannot identify the owner of the pending mark.
	sendTestPacket(h, base.Add(5*time.Millisecond), 1, "stream")
	if b.notifications != 0 || c.notifications != 0 {
		t.Fatal("replacement inherited another controller's empty interval")
	}
	recordEmptyAt(h, base.Add(6*time.Millisecond))
	sendTestPacket(h, base.Add(11*time.Millisecond), 2, "stream")
	if c.notifications != 1 {
		t.Fatal("new controller cannot establish its own empty interval")
	}
}
func TestAppLimitedLifecycleInvalidation(t *testing.T) {
	for _, kind := range []string{"migration", "retry"} {
		t.Run(kind, func(t *testing.T) {
			h, _ := newAppLimitedHandler()
			base := monotime.Now()
			recordEmptyAt(h, base)
			if kind == "migration" {
				h.MigratedPath(base.Add(time.Millisecond), 1200)
			} else {
				h.ptoCount = 1
				h.ResetForRetry(base.Add(time.Millisecond))
			}
			if !h.appLimitedReadiness.observation(monotime.Now()).start.IsZero() {
				t.Fatal("path lifecycle retained old empty interval")
			}
		})
	}
}
func TestAppLimitedPacingKeepsEligibleEmptyMarker(t *testing.T) {
	h, c := newAppLimitedHandler()
	base := monotime.Now()
	recordEmptyAt(h, base)
	c.pacing = true
	if h.SendMode(base.Add(time.Millisecond)) != SendPacingLimited {
		t.Fatal("pacing path not exercised")
	}
	if h.appLimitedReadiness.observation(monotime.Now()).start != base {
		t.Fatal("pacing alone invalidated eligible empty marker")
	}
	c.pacing = false
	sendTestPacket(h, base.Add(5*time.Millisecond), 1, "stream")
	if c.notifications != 1 {
		t.Fatal("eligible marker lost across ACK-service pacing")
	}
}
func TestAppLimitedRetransmissionQueueInvalidatesMarker(t *testing.T) {
	h, _ := newAppLimitedHandler()
	base := monotime.Now()
	recordEmptyAt(h, base)
	p := &packet{Frames: []Frame{{Frame: &wire.PingFrame{}}}}
	h.queueFramesForRetransmission(p)
	if !h.appLimitedReadiness.observation(monotime.Now()).start.IsZero() {
		t.Fatal("retransmission scheduling retained application-empty evidence")
	}
}

func TestAppLimitedControllerChangeDuringPublication(t *testing.T) {
	h, _ := newAppLimitedHandler()
	recordEmptyAt(h, monotime.Now().Add(-time.Second))
	h.appLimitedReadiness.BeginPublication()
	c := &appLimitedController{canSend: true}
	h.SetCongestionControl(c)
	h.SendMode(monotime.Now())
	h.MaybeNotifyAppLimited(h.appLimitedReadiness.BeginProbe())
	if !h.appLimitedReadiness.observation(monotime.Now()).start.IsZero() {
		t.Fatal("controller change rearmed during active publication")
	}
	h.appLimitedReadiness.EndPublication()
	sendTestPacket(h, monotime.Now().Add(time.Second), 1, "stream")
	if c.notifications != 0 {
		t.Fatal("controller inherited old or unpublished epoch")
	}
}
