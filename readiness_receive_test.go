package quic

import (
	"testing"
	"time"

	"github.com/sagernet/quic-go/internal/ackhandler"
	"github.com/sagernet/quic-go/internal/monotime"
	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/internal/utils"
)

type receiveReadinessSender struct {
	readiness            *ackhandler.AppLimitedReadiness
	begins, ends, active int
	beforeBegin          func()
	onControl            func()
}

func (s *receiveReadinessSender) beginAppDataPublication() {
	if s.beforeBegin != nil {
		s.beforeBegin()
	}
	s.readiness.BeginPublication()
	s.begins++
	s.active++
}
func (s *receiveReadinessSender) endAppDataPublication() {
	s.readiness.EndPublication()
	s.ends++
	s.active--
}
func (*receiveReadinessSender) onHasConnectionData()                           {}
func (*receiveReadinessSender) onHasStreamData(protocol.StreamID, *SendStream) {}
func (s *receiveReadinessSender) onHasStreamControlFrame(protocol.StreamID, streamControlFrameGetter) {
	if s.onControl != nil {
		s.onControl()
	}
}
func (*receiveReadinessSender) onStreamCompleted(protocol.StreamID) {}

func newReceiveReadinessFlow(window protocol.ByteCount, readiness *ackhandler.AppLimitedReadiness) *connectionFlowController {
	logger := utils.DefaultLogger.WithPrefix("receive-readiness-unit")
	logger.SetLogLevel(utils.LogLevelNothing)
	c := newConnectionFlowController(window, 4*window, func(protocol.ByteCount) bool { return true }, utils.NewRTTStats(), logger)
	c.appLimitedReadiness = readiness
	return c
}

func TestReadinessReceiveWindowPublication(t *testing.T) {
	r := new(ackhandler.AppLimitedReadiness)
	cfc := newReceiveReadinessFlow(10000, r)
	sfc := newStreamFlowController(0, cfc, 100, 100, 0, utils.NewRTTStats(), cfc.logger)
	sender := &receiveReadinessSender{readiness: r}
	s := newReceiveStream(0, sender, sfc)
	// Keep the stream open: receiving its final offset suppresses window updates.
	s.currentFrame = make([]byte, 100)
	crossing := 100 - int(protocol.ByteCount(float64(100)*(1-protocol.WindowUpdateThreshold)))
	if n, err := s.Read(make([]byte, crossing-1)); err != nil || n != crossing-1 {
		t.Fatalf("subthreshold read: n=%d err=%v", n, err)
	}
	if sender.begins != 0 || sender.ends != 0 {
		t.Fatal("subthreshold read published control readiness")
	}
	sender.beforeBegin = func() {
		if sfc.bytesRead != protocol.ByteCount(crossing-1) || s.queuedMaxStreamData {
			t.Fatal("publication began after the source threshold or control flag changed")
		}
	}
	var activeProbe ackhandler.AppLimitedProbe
	sender.onControl = func() {
		if sender.active != 1 || !s.queuedMaxStreamData {
			t.Fatal("publication did not span source mutation through activation")
		}
		activeProbe = r.BeginProbe()
	}
	if n, err := s.Read(make([]byte, 1)); err != nil || n != 1 {
		t.Fatalf("threshold read: n=%d err=%v", n, err)
	}
	if sender.begins != 1 || sender.ends != 1 || sender.active != 0 {
		t.Fatal("threshold publication was not completed exactly once")
	}
	if activeProbe == r.BeginProbe() {
		t.Fatal("empty-probe eligibility did not change after activation completed")
	}
	sender.beforeBegin = func() { t.Fatal("already pending window update published again") }
	sender.onControl = nil
	if _, err := s.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if sender.begins != 1 || sender.ends != 1 {
		t.Fatal("repeated pending update changed publication count")
	}
}

func TestReadinessReceiveCancellationPublication(t *testing.T) {
	r := new(ackhandler.AppLimitedReadiness)
	cfc := newReceiveReadinessFlow(1000, r)
	sfc := newStreamFlowController(0, cfc, 100, 100, 0, utils.NewRTTStats(), cfc.logger)
	sender := &receiveReadinessSender{readiness: r}
	s := newReceiveStream(0, sender, sfc)
	sender.beforeBegin = func() {
		if s.queuedStopSending {
			t.Fatal("STOP_SENDING was visible before publication began")
		}
	}
	sender.onControl = func() {
		if sender.active != 1 || !s.queuedStopSending {
			t.Fatal("STOP_SENDING publication ended before activation")
		}
	}
	s.CancelRead(7)
	s.CancelRead(7)
	if sender.begins != 1 || sender.ends != 1 || sender.active != 0 {
		t.Fatal("cancellation publication was not exactly once")
	}
}

func TestReadinessReceivePartialReadCompletesPublication(t *testing.T) {
	r := new(ackhandler.AppLimitedReadiness)
	cfc := newReceiveReadinessFlow(10000, r)
	sfc := newStreamFlowController(0, cfc, 100, 100, 0, utils.NewRTTStats(), cfc.logger)
	sender := &receiveReadinessSender{readiness: r}
	s := newReceiveStream(0, sender, sfc)
	crossing := 100 - int(protocol.ByteCount(float64(100)*(1-protocol.WindowUpdateThreshold)))
	s.currentFrame = make([]byte, crossing)
	// Bound a regression that waits for another frame after publishing readiness.
	// The correct path returns the already-read bytes without waiting for this deadline.
	s.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := s.Read(make([]byte, crossing+1)); n != crossing || err != nil {
		t.Fatalf("partial read waited or failed: n=%d err=%v", n, err)
	}
	if sender.begins != 1 || sender.ends != 1 || sender.active != 0 {
		t.Fatal("partial read retained an active publication")
	}
}

func TestReadinessReceiveNoPublicationWithoutNewControl(t *testing.T) {
	for _, final := range []bool{false, true} {
		r := new(ackhandler.AppLimitedReadiness)
		cfc := newReceiveReadinessFlow(10000, r)
		sfc := newStreamFlowController(0, cfc, 100, 100, 0, utils.NewRTTStats(), cfc.logger)
		sender := &receiveReadinessSender{readiness: r}
		s := newReceiveStream(0, sender, sfc)
		if final {
			sfc.receivedFinalOffset = true
			s.currentFrame = make([]byte, 100)
			if _, err := s.Read(make([]byte, 100)); err != nil {
				t.Fatal(err)
			}
		} else {
			s.SetReadDeadline(time.Now().Add(-time.Second))
			if n, err := s.Read(make([]byte, 1)); n != 0 || err != errDeadline {
				t.Fatalf("expired empty read: n=%d err=%v", n, err)
			}
		}
		if sender.begins != 0 || sender.ends != 0 {
			t.Fatalf("new stream control was not available (final=%v), but publication started", final)
		}
	}
}

func TestReadinessConnectionWindowTransitions(t *testing.T) {
	r := new(ackhandler.AppLimitedReadiness)
	c := newReceiveReadinessFlow(100, r)
	crossing := protocol.ByteCount(100) - protocol.ByteCount(float64(100)*(1-protocol.WindowUpdateThreshold))
	before := r.BeginProbe()
	if c.AddBytesRead(crossing-1) || r.BeginProbe() != before {
		t.Fatal("subthreshold connection read published readiness")
	}
	if !c.AddBytesRead(1) || r.BeginProbe() == before {
		t.Fatal("connection threshold transition did not publish")
	}
	before = r.BeginProbe()
	if !c.AddBytesRead(1) || r.BeginProbe() != before {
		t.Fatal("already pending connection update published again")
	}
	// Consuming the update permits a later independent threshold transition.
	c.GetWindowUpdate(monotime.Now())
	before = r.BeginProbe()
	if !c.AddBytesRead(crossing) || r.BeginProbe() == before {
		t.Fatal("new connection window epoch did not publish")
	}
}

func TestReadinessConnectionWindowGrowthAndAbandon(t *testing.T) {
	t.Run("growth", func(t *testing.T) {
		r := new(ackhandler.AppLimitedReadiness)
		c := newReceiveReadinessFlow(1000, r)
		before := r.BeginProbe()
		c.EnsureMinimumWindowSize(1100, monotime.Now())
		if r.BeginProbe() != before || c.HasPendingWindowUpdate() {
			t.Fatal("growth without a pending update published readiness")
		}
		c.EnsureMinimumWindowSize(2000, monotime.Now())
		if r.BeginProbe() == before || !c.HasPendingWindowUpdate() {
			t.Fatal("window growth threshold transition did not publish")
		}
		before = r.BeginProbe()
		c.EnsureMinimumWindowSize(3000, monotime.Now())
		if r.BeginProbe() != before {
			t.Fatal("growth of already pending update published again")
		}
	})
	t.Run("abandon", func(t *testing.T) {
		r := new(ackhandler.AppLimitedReadiness)
		c := newReceiveReadinessFlow(100, r)
		s := newStreamFlowController(0, c, 100, 100, 0, utils.NewRTTStats(), c.logger)
		s.highestReceived = 100
		before := r.BeginProbe()
		s.Abandon()
		if r.BeginProbe() == before || !c.HasPendingWindowUpdate() {
			t.Fatal("abandoned bytes did not publish connection-window readiness")
		}
		before = r.BeginProbe()
		s.Abandon()
		if r.BeginProbe() != before {
			t.Fatal("repeated abandon published readiness")
		}
	})
}

func TestReadinessConnectionSendCreditTransitions(t *testing.T) {
	r := new(ackhandler.AppLimitedReadiness)
	c := newReceiveReadinessFlow(100, r)
	before := r.BeginProbe()
	if !c.UpdateSendWindow(100) || r.BeginProbe() == before {
		t.Fatal("increased send credit did not publish readiness")
	}
	before = r.BeginProbe()
	if c.UpdateSendWindow(100) || c.UpdateSendWindow(99) || r.BeginProbe() != before {
		t.Fatal("duplicate or reordered send credit published readiness")
	}
}
