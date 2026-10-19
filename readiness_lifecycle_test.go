package quic

import (
	"errors"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/quic-go/internal/ackhandler"
	"github.com/sagernet/quic-go/internal/monotime"
	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/internal/utils"
	"github.com/sagernet/quic-go/internal/wire"
)

type lifecycleReadinessSender struct {
	streamSender
	begins               atomic.Int64
	ends                 atomic.Int64
	active               atomic.Int64
	completedPublication chan struct{}
}

func (s *lifecycleReadinessSender) beginAppDataPublication() {
	s.streamSender.beginAppDataPublication()
	s.begins.Add(1)
	s.active.Add(1)
}

func (s *lifecycleReadinessSender) endAppDataPublication() {
	s.streamSender.endAppDataPublication()
	s.ends.Add(1)
	s.active.Add(-1)
	s.completedPublication <- struct{}{}
}

// The socket-free scheduler fixture has no streamsMap. Publication, activation,
// framing and packetization still use the real connection and stream objects.
func (*lifecycleReadinessSender) onStreamCompleted(protocol.StreamID) {}

func newLifecycleReadinessStream(t *testing.T) (*Conn, *SendStream, *lifecycleReadinessSender) {
	t.Helper()
	c, s, _, _, _ := newBacklogConn(t)
	sender := &lifecycleReadinessSender{streamSender: c, completedPublication: make(chan struct{}, 16)}
	s.sender = sender
	return c, s, sender
}

func waitLifecyclePublication(t *testing.T, sender *lifecycleReadinessSender) {
	t.Helper()
	select {
	case <-sender.completedPublication:
	case <-time.After(2 * time.Second):
		t.Fatal("source publication did not complete")
	}
}

func assertLifecyclePublicationsBalanced(t *testing.T, sender *lifecycleReadinessSender) {
	t.Helper()
	if sender.active.Load() != 0 || sender.begins.Load() != sender.ends.Load() {
		t.Fatalf("unbalanced publication: begins=%d ends=%d active=%d", sender.begins.Load(), sender.ends.Load(), sender.active.Load())
	}
}

// This is the handler/tracker boundary test: assume a later ordinary attempt is
// empty, then prove outstanding publisher state cannot silently suppress it.
// The unrelated source queues need not be drained to test that state invariant.
func assertLifecycleIdleEvidenceAvailable(t *testing.T, readiness *ackhandler.AppLimitedReadiness) {
	t.Helper()
	logger := utils.DefaultLogger.WithPrefix("lifecycle-readiness-unit")
	logger.SetLogLevel(utils.LogLevelNothing)
	h := ackhandler.NewSentPacketHandler(0, 1200, utils.NewRTTStats(), &utils.ConnectionStats{}, true, false, func(protocol.PacketNumber) {}, protocol.PerspectiveClient, false, nil, logger, readiness)
	cc := &backpressureController{}
	h.SetCongestionControl(cc)
	h.ResetAppLimited()
	h.MaybeNotifyAppLimited(readiness.BeginProbe())
	h.SentPacket(monotime.Now().Add(5*time.Millisecond), 0, protocol.InvalidPacketNumber, nil, []ackhandler.Frame{{Frame: &wire.PingFrame{}}}, protocol.Encryption1RTT, protocol.ECNNon, 100, false, false)
	if cc.notifications != 1 {
		t.Fatal("later idle evidence was suppressed by a leaked active publisher")
	}
}

type lifecycleWriteResult struct {
	n   int
	err error
}

func waitLifecycleWrite(t *testing.T, result <-chan lifecycleWriteResult) lifecycleWriteResult {
	t.Helper()
	select {
	case r := <-result:
		return r
	case <-time.After(2 * time.Second):
		t.Fatal("write did not unblock")
		return lifecycleWriteResult{}
	}
}

func TestReadinessLifecycleWriteWithLimit(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		c, s, sender := newLifecycleReadinessStream(t)
		n, err := s.WriteWithLimit(nil, func(int) int { t.Error("empty write invoked limiter"); return 0 })
		if n != 0 || err != nil || sender.begins.Load() != 0 {
			t.Fatalf("empty limited write: n=%d err=%v begins=%d", n, err, sender.begins.Load())
		}
		assertLifecyclePublicationsBalanced(t, sender)
		assertLifecycleIdleEvidenceAvailable(t, c.appLimitedReadiness)
	})
	for _, limit := range []int{0, -1} {
		t.Run(map[int]string{0: "zero-credit", -1: "negative-credit-clamped"}[limit], func(t *testing.T) {
			c, s, sender := newLifecycleReadinessStream(t)
			var limiterCalls atomic.Int64
			result := make(chan lifecycleWriteResult, 1)
			go func() {
				n, err := s.WriteWithLimit([]byte("limited-data"), func(int) int { limiterCalls.Add(1); return limit })
				result <- lifecycleWriteResult{n, err}
			}()
			defer s.closeForShutdown(errors.New("test cleanup"))
			waitLifecyclePublication(t, sender)
			assertLifecyclePublicationsBalanced(t, sender)
			if err := c.triggerSending(monotime.Now()); err != nil {
				t.Fatal(err)
			}
			r := waitLifecycleWrite(t, result)
			if r.n != 0 || !errors.Is(r.err, ErrWriteLimitReached) || limiterCalls.Load() != 1 {
				t.Fatalf("rejected limited write: n=%d err=%v limiter calls=%d", r.n, r.err, limiterCalls.Load())
			}
			assertLifecyclePublicationsBalanced(t, sender)
			assertLifecycleIdleEvidenceAvailable(t, c.appLimitedReadiness)
		})
	}
}

func TestReadinessLifecycleBlockedWriteTermination(t *testing.T) {
	for _, termination := range []string{"deadline", "cancel", "shutdown"} {
		t.Run(termination, func(t *testing.T) {
			c, s, sender := newLifecycleReadinessStream(t)
			shutdownErr := errors.New("synthetic stream shutdown")
			result := make(chan lifecycleWriteResult, 1)
			go func() {
				n, err := s.Write(make([]byte, int(protocol.MaxPacketBufferSize)+1))
				result <- lifecycleWriteResult{n, err}
			}()
			defer s.closeForShutdown(shutdownErr)
			waitLifecyclePublication(t, sender)
			assertLifecyclePublicationsBalanced(t, sender)
			assertLifecycleIdleEvidenceAvailable(t, c.appLimitedReadiness)
			before := sender.begins.Load()
			if err := s.TryWriteAll([]byte("busy")); !errors.Is(err, ErrWouldBlock) || sender.begins.Load() != before {
				t.Fatalf("TryWriteAll while Write is blocked: err=%v", err)
			}
			switch termination {
			case "deadline":
				s.SetWriteDeadline(time.Now().Add(-time.Second))
			case "cancel":
				s.CancelWrite(19)
			case "shutdown":
				s.closeForShutdown(shutdownErr)
			}
			r := waitLifecycleWrite(t, result)
			if r.n != 0 || r.err == nil {
				t.Fatalf("terminated write: n=%d err=%v", r.n, r.err)
			}
			switch termination {
			case "deadline":
				if !errors.Is(r.err, errDeadline) {
					t.Fatal(r.err)
				}
			case "cancel":
				var streamErr *StreamError
				if !errors.As(r.err, &streamErr) || streamErr.ErrorCode != 19 {
					t.Fatal(r.err)
				}
			case "shutdown":
				if !errors.Is(r.err, shutdownErr) {
					t.Fatal(r.err)
				}
			}
			assertLifecyclePublicationsBalanced(t, sender)
			before = sender.begins.Load()
			if _, err := s.Write([]byte("rejected")); err == nil || sender.begins.Load() != before {
				t.Fatal("terminal-state Write published or unexpectedly succeeded")
			}
			assertLifecycleIdleEvidenceAvailable(t, c.appLimitedReadiness)
		})
	}
}

func TestReadinessLifecycleRejectedTryWriteAll(t *testing.T) {
	for _, state := range []string{"empty", "no-credit", "closed", "cancelled", "shutdown"} {
		t.Run(state, func(t *testing.T) {
			c, s, sender := newLifecycleReadinessStream(t)
			payload := []byte("data")
			switch state {
			case "empty":
				payload = nil
			case "no-credit":
				s.flowController.sendWindow = 0
			case "closed":
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				s.CancelWrite(21)
			case "shutdown":
				s.closeForShutdown(errors.New("synthetic shutdown"))
			}
			before := sender.begins.Load()
			err := s.TryWriteAll(payload)
			if (state == "empty") != (err == nil) || sender.begins.Load() != before {
				t.Fatalf("TryWriteAll state=%s err=%v changed publication count", state, err)
			}
			if state == "no-credit" && !errors.Is(err, ErrWouldBlock) {
				t.Fatal(err)
			}
			assertLifecyclePublicationsBalanced(t, sender)
			assertLifecycleIdleEvidenceAvailable(t, c.appLimitedReadiness)
		})
	}
}

func TestReadinessLifecycleRepeatedFINAndCancelWrite(t *testing.T) {
	for _, first := range []string{"FIN", "cancel"} {
		t.Run(first, func(t *testing.T) {
			c, s, sender := newLifecycleReadinessStream(t)
			if first == "FIN" {
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				if sender.begins.Load() != 1 {
					t.Fatal("repeated FIN published twice")
				}
			}
			s.CancelWrite(27)
			before := sender.begins.Load()
			s.CancelWrite(28)
			if sender.begins.Load() != before {
				t.Fatal("repeated cancellation published twice")
			}
			err := s.Close()
			if first == "cancel" && err == nil {
				t.Fatal("Close after cancellation succeeded")
			}
			if sender.begins.Load() != before {
				t.Fatal("Close after cancellation started a publication")
			}
			assertLifecyclePublicationsBalanced(t, sender)
			assertLifecycleIdleEvidenceAvailable(t, c.appLimitedReadiness)
		})
	}
}

func TestReadinessLifecycleFullDatagramQueueShutdown(t *testing.T) {
	r := new(ackhandler.AppLimitedReadiness)
	logger := utils.DefaultLogger.WithPrefix("datagram-lifecycle-unit")
	logger.SetLogLevel(utils.LogLevelNothing)
	q := newDatagramQueue(func() {}, logger, r)
	for i := 0; i < maxDatagramSendQueueLen; i++ {
		if err := q.Add(&wire.DatagramFrame{Data: []byte{byte(i)}}); err != nil {
			t.Fatal(err)
		}
	}
	before := r.BeginProbe()
	// Add drains this existing notification only after observing the full queue.
	// Its disappearance, followed by acquiring sendMx, is a wait-path barrier.
	q.sent <- struct{}{}
	result := make(chan error, 1)
	go func() { result <- q.Add(&wire.DatagramFrame{Data: []byte("blocked")}) }()
	shutdownErr := errors.New("synthetic DATAGRAM shutdown")
	closed := false
	defer func() {
		if !closed {
			q.CloseWithError(shutdownErr)
		}
	}()
	deadline := time.Now().Add(2 * time.Second)
	for len(q.sent) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("DATAGRAM Add did not enter the full-queue wait path")
		}
		runtime.Gosched()
	}
	q.sendMx.Lock()
	q.sendMx.Unlock()
	select {
	case err := <-result:
		t.Fatalf("full-queue Add returned early: %v", err)
	default:
	}
	if r.BeginProbe() != before {
		t.Fatal("blocked DATAGRAM Add began a publication")
	}
	assertLifecycleIdleEvidenceAvailable(t, r)
	q.CloseWithError(shutdownErr)
	closed = true
	select {
	case err := <-result:
		if !errors.Is(err, shutdownErr) {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DATAGRAM Add did not unblock on shutdown")
	}
	if r.BeginProbe() != before {
		t.Fatal("shutdown of blocked DATAGRAM Add changed publication state")
	}
	assertLifecycleIdleEvidenceAvailable(t, r)
}
