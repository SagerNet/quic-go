package quic

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	ext "github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/internal/monotime"
	"github.com/sagernet/quic-go/internal/protocol"
	"github.com/sagernet/quic-go/internal/utils"
	"github.com/sagernet/quic-go/internal/wire"
	publicmono "github.com/sagernet/quic-go/monotime"
)

// The recording policy spends its remaining pacing budget on a pure ACK too.
// This holds the next ordinary empty probe until later application data arrives.
type creditReadinessCC struct{ backlogCC }

func (c *creditReadinessCC) OnPacketSent(now publicmono.Time, flight ext.ByteCount, pn ext.PacketNumber, size ext.ByteCount, ack bool) {
	c.backlogCC.OnPacketSent(now, flight, pn, size, ack)
	c.pacing = false
}

func TestCreditUpdateWithoutReadyDataPreservesIdle(t *testing.T) {
	for _, gso := range []bool{false, true} {
		for _, exhausted := range []bool{false, true} {
			for _, update := range []bool{false, true} {
				t.Run(fmt.Sprintf("GSO=%v/exhausted=%v/MAX_DATA=%v", gso, exhausted, update), func(t *testing.T) {
					c, s, _, a, p := newBacklogConn(t)
					c.conn = backlogSendConn{gso: gso}
					if exhausted {
						c.connFlowController.sendWindow = 0
					}
					cc := &creditReadinessCC{backlogCC: backlogCC{pacing: true}}
					c.sentPacketHandler.SetCongestionControl(cc)
					start := monotime.Now()
					if err := c.triggerSending(start); err != nil {
						t.Fatal(err)
					}
					if update {
						receiveConnectionCredit(t, c, 2<<20)
					}
					if elapsed := monotime.Now().Sub(start); elapsed >= 2*time.Millisecond {
						t.Skipf("invalid short-credit sample: %v", elapsed)
					}
					a.enabled = true
					if err := c.triggerSending(monotime.Now()); err != nil {
						t.Fatal(err)
					}
					if len(p.sent) != 1 || p.sent[0].Ack == nil || len(p.sent[0].StreamFrames) != 0 || len(p.sent[0].Frames) != 0 || cc.pacing {
						t.Fatal("pure ACK did not exhaust recording pacer")
					}
					time.Sleep(3 * time.Millisecond)
					if exhausted && !update {
						receiveConnectionCredit(t, c, 2<<20)
					}
					if err := s.TryWriteAll([]byte("after-empty-credit")); err != nil {
						t.Fatal(err)
					}
					cc.pacing = true
					if err := c.triggerSending(monotime.Now()); err != nil {
						t.Fatal(err)
					}
					if len(p.sent) != 2 || len(p.sent[1].StreamFrames) != 1 {
						t.Fatal("later application data was not sent")
					}
					if cc.notifications != 1 {
						t.Fatalf("empty MAX_DATA traffic consumed genuine idle: notifications=%d want1", cc.notifications)
					}
				})
			}
		}
	}
}

func receiveConnectionCredit(t *testing.T, c *Conn, limit protocol.ByteCount) {
	t.Helper()
	if _, err := c.handleFrame(&wire.MaxDataFrame{MaximumData: limit}, protocol.Encryption1RTT, protocol.ConnectionID{}, monotime.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestCreditUpdateRequiresUsefulUnblocking(t *testing.T) {
	for _, gso := range []bool{false, true} {
		for _, first := range []string{"connection", "stream"} {
			t.Run(fmt.Sprintf("GSO=%v/%s-first", gso, first), func(t *testing.T) {
				c, s, _, a, p := newBacklogConn(t)
				c.conn = backlogSendConn{gso: gso}
				cc := &creditReadinessCC{backlogCC: backlogCC{pacing: true}}
				c.sentPacketHandler.SetCongestionControl(cc)
				c.connFlowController.sendWindow = 0
				s.flowController.sendWindow = 0
				if _, err := s.Write([]byte("both-credits-blocked")); err != nil {
					t.Fatal(err)
				}
				start := monotime.Now()
				if err := c.triggerSending(start); err != nil {
					t.Fatal(err)
				}
				if len(p.sent) != 0 {
					t.Fatal("flow-blocked fixture emitted data")
				}
				if first == "connection" {
					receiveConnectionCredit(t, c, 1000)
				} else {
					s.updateSendWindow(1000)
				}
				if elapsed := monotime.Now().Sub(start); elapsed >= 2*time.Millisecond {
					t.Skipf("invalid short first-credit sample: %v", elapsed)
				}
				a.enabled = true
				if err := c.triggerSending(monotime.Now()); err != nil {
					t.Fatal(err)
				}
				if len(p.sent) != 1 || len(p.sent[0].StreamFrames) != 0 || cc.pacing {
					t.Fatal("first credit unexpectedly made data sendable")
				}
				time.Sleep(3 * time.Millisecond)
				if first == "connection" {
					s.updateSendWindow(1000)
				} else {
					receiveConnectionCredit(t, c, 1000)
				}
				cc.pacing = true
				if err := c.triggerSending(monotime.Now()); err != nil {
					t.Fatal(err)
				}
				if len(p.sent) != 2 || len(p.sent[1].StreamFrames) != 1 || cc.notifications != 1 {
					t.Fatalf("later useful credit lost genuine idle: packets=%d notifications=%d", len(p.sent), cc.notifications)
				}
			})
		}
	}
}

func TestCreditRestorationCapsQueuedPacing(t *testing.T) {
	for _, gso := range []bool{false, true} {
		for _, scope := range []string{"connection", "stream"} {
			for _, idle := range []time.Duration{0, 3 * time.Millisecond} {
				t.Run(fmt.Sprintf("GSO=%v/%s/%s", gso, scope, idle), func(t *testing.T) {
					c, s, _, a, p := newBacklogConn(t)
					c.conn = backlogSendConn{gso: gso}
					cc := &creditReadinessCC{backlogCC: backlogCC{pacing: true}}
					c.sentPacketHandler.SetCongestionControl(cc)
					if scope == "connection" {
						c.connFlowController.sendWindow = 0
					} else {
						s.flowController.sendWindow = 0
					}
					if _, err := s.Write([]byte("credit-wakeup")); err != nil {
						t.Fatal(err)
					}
					start := monotime.Now()
					if err := c.triggerSending(start); err != nil {
						t.Fatal(err)
					}
					a.enabled = true
					if err := c.triggerSending(monotime.Now()); err != nil {
						t.Fatal(err)
					}
					if len(p.sent) != 1 || p.sent[0].Ack == nil || cc.pacing {
						t.Fatal("expected pure ACK budget exhaustion")
					}
					time.Sleep(idle)
					if scope == "connection" {
						receiveConnectionCredit(t, c, 1000)
					} else {
						s.updateSendWindow(1000)
					}
					elapsed := monotime.Now().Sub(start)
					if idle == 0 && elapsed >= 2*time.Millisecond {
						t.Skipf("invalid short useful-credit sample: %v", elapsed)
					}
					time.Sleep(3 * time.Millisecond)
					cc.pacing = true
					if err := c.triggerSending(monotime.Now()); err != nil {
						t.Fatal(err)
					}
					want := 0
					if idle > 0 {
						want = 1
					}
					if cc.notifications != want || len(p.sent) != 2 || len(p.sent[1].StreamFrames) != 1 {
						t.Fatalf("credit readiness cap: notifications=%d want%d packets=%d", cc.notifications, want, len(p.sent))
					}
				})
			}
		}
	}
}

func TestCreditReadinessEligibility(t *testing.T) {
	for _, scope := range []string{"connection", "stream"} {
		for _, kind := range []string{"queued", "empty", "available", "duplicate", "reordered", "other-credit-blocked", "reserved", "reserved-prefix", "retransmission-prefix", "FIN-only", "known-limited", "unevaluated-limiter", "shutdown", "cancelled", "reliable-prefix", "reliable-exhausted", "empty-frame"} {
			t.Run(scope+"/"+kind, func(t *testing.T) {
				c, s, _, _, _ := newBacklogConn(t)
				if kind != "empty" && kind != "FIN-only" && kind != "reserved" && kind != "reserved-prefix" {
					if _, err := s.Write([]byte("queued-payload")); err != nil {
						t.Fatal(err)
					}
				}
				if kind == "reserved" || kind == "reserved-prefix" {
					if err := s.TryWriteAll([]byte("reserved-payload")); err != nil {
						t.Fatal(err)
					}
					if kind == "reserved-prefix" {
						s.dataForWriting = []byte("unreserved-suffix")
					}
				}
				switch kind {
				case "FIN-only":
					if err := s.Close(); err != nil {
						t.Fatal(err)
					}
				case "retransmission-prefix":
					s.retransmissionQueue = []*wire.StreamFrame{{Data: []byte("retry")}}
				case "known-limited":
					s.writeLimited = true
				case "unevaluated-limiter":
					s.dataForWriting = append([]byte(nil), s.nextFrame.Data...)
					s.nextFrame.PutBack()
					s.nextFrame = nil
					s.writeLimiter = func(int) int { t.Fatal("readiness speculatively invoked limiter"); return 0 }
				case "shutdown":
					s.closeForShutdown(errors.New("fixture shutdown"))
				case "cancelled":
					s.CancelWrite(1)
				case "reliable-prefix", "reliable-exhausted":
					s.supportsResetStreamAt = true
					s.reliableSize = 3
					s.CancelWrite(1)
					if kind == "reliable-exhausted" {
						s.writeOffset = 3
					}
				case "empty-frame":
					s.nextFrame.Data = s.nextFrame.Data[:0]
				}
				if scope == "connection" {
					c.connFlowController.sendWindow = c.connFlowController.bytesSent
				} else {
					s.flowController.sendWindow = s.flowController.bytesSent
				}
				if kind == "other-credit-blocked" {
					c.connFlowController.sendWindow = c.connFlowController.bytesSent
					s.flowController.sendWindow = s.flowController.bytesSent
				}
				if kind == "available" {
					if scope == "connection" {
						c.connFlowController.sendWindow += 100
					} else {
						s.flowController.sendWindow += 100
					}
				}
				limit := protocol.ByteCount(10000)
				if kind == "duplicate" || kind == "reordered" {
					if scope == "connection" {
						c.connFlowController.sendWindow = 100
						limit = 100
					} else {
						s.flowController.sendWindow = 100
						limit = 100
					}
					if kind == "reordered" {
						limit--
					}
				}
				before := c.appLimitedReadiness.BeginProbe()
				if scope == "connection" {
					receiveConnectionCredit(t, c, limit)
				} else {
					s.updateSendWindow(limit)
				}
				changed := c.appLimitedReadiness.BeginProbe() != before
				want := kind == "queued" || kind == "reliable-prefix" || kind == "unevaluated-limiter"
				if changed != want {
					t.Fatalf("readiness publication=%v want%v", changed, want)
				}
			})
		}
	}
}

func TestCreditUpdateDuringStreamPublication(t *testing.T) {
	for _, gso := range []bool{false, true} {
		t.Run(fmt.Sprintf("GSO=%v", gso), func(t *testing.T) {
			c, s, cc, _, p := newBacklogConn(t)
			c.conn = backlogSendConn{gso: gso}
			c.connFlowController.sendWindow = 0
			paused := &pausedReadinessSender{streamSender: c, published: make(chan struct{}), activate: make(chan struct{})}
			s.sender = paused
			done := make(chan error, 1)
			go func() { _, err := s.Write([]byte("source-before-activation")); done <- err }()
			<-paused.published
			if err := c.triggerSending(monotime.Now()); err != nil {
				t.Fatal(err)
			}
			receiveConnectionCredit(t, c, 1000)
			time.Sleep(3 * time.Millisecond)
			close(paused.activate)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if err := c.triggerSending(monotime.Now()); err != nil {
				t.Fatal(err)
			}
			if cc.notifications != 0 || len(p.sent) != 1 || len(p.sent[0].StreamFrames) != 1 {
				t.Fatal("credit update exposed an idle epoch during source publication")
			}
		})
	}
}

func TestCreditUpdateConcurrentReservation(t *testing.T) {
	for iteration := 0; iteration < 100; iteration++ {
		c, s, _, _, _ := newBacklogConn(t)
		c.connFlowController.sendWindow = 0
		if _, err := s.Write([]byte("unreserved")); err != nil {
			t.Fatal(err)
		}
		other := newSendStream(context.Background(), 4, c, newStreamFlowController(4, c.connFlowController, 1<<20, 1<<20, 1<<20, utils.NewRTTStats(), c.logger), false)
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		var writeErr, updateErr error
		go func() {
			defer wg.Done()
			<-start
			_, updateErr = c.handleFrame(&wire.MaxDataFrame{MaximumData: 1000}, protocol.Encryption1RTT, protocol.ConnectionID{}, monotime.Now())
		}()
		go func() { defer wg.Done(); <-start; writeErr = other.TryWriteAll(make([]byte, 1000)) }()
		close(start)
		wg.Wait()
		if updateErr != nil {
			t.Fatal(updateErr)
		}
		if writeErr != nil && writeErr != ErrWouldBlock {
			t.Fatal(writeErr)
		}
		if writeErr == nil && (!other.nextFrameReserved || c.connFlowController.SendWindowSize() != 0) {
			t.Fatal("concurrent reservation was not accounted atomically")
		}
		// The original stream remains queued either way; restore credit before
		// packetizing so the test does not leave a blocked writer or socket work.
		receiveConnectionCredit(t, c, 2000)
		if err := c.triggerSending(monotime.Now()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCreditUpdateFindsEligibleActiveStream(t *testing.T) {
	for iteration := 0; iteration < 20; iteration++ {
		c, blocked, _, _, _ := newBacklogConn(t)
		c.connFlowController.sendWindow = 0
		blocked.flowController.sendWindow = 0
		if _, err := blocked.Write([]byte("still-stream-blocked")); err != nil {
			t.Fatal(err)
		}
		eligible := newSendStream(context.Background(), 4, c, newStreamFlowController(4, c.connFlowController, 1<<20, 1<<20, 1<<20, utils.NewRTTStats(), c.logger), false)
		if _, err := eligible.Write([]byte("connection-blocked")); err != nil {
			t.Fatal(err)
		}
		before := c.appLimitedReadiness.BeginProbe()
		receiveConnectionCredit(t, c, 1000)
		if c.appLimitedReadiness.BeginProbe() == before {
			t.Fatal("ineligible stream hid an eligible active stream")
		}
		if c.connFlowController.SendWindowSize() != 1000 {
			t.Fatal("credit update was not applied once")
		}
	}
}
