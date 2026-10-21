package ackhandler

import (
	"sync"
	"testing"
	"time"

	"github.com/sagernet/quic-go/internal/monotime"
)

func observeReadinessAt(s *AppLimitedReadiness, at monotime.Time, generation uint64) {
	s.observeEmpty(s.BeginProbe(), generation)
	s.mutex.Lock()
	s.start = at
	s.mutex.Unlock()
}
func publishReadinessAt(s *AppLimitedReadiness, at monotime.Time) {
	s.BeginPublication()
	s.mutex.Lock()
	s.firstReady = at
	s.mutex.Unlock()
	s.EndPublication()
}
func TestReadinessCapsAtFirstPublication(t *testing.T) {
	for _, idle := range []time.Duration{500 * time.Microsecond, 3 * time.Millisecond} {
		t.Run(idle.String(), func(t *testing.T) {
			s := new(AppLimitedReadiness)
			base := monotime.Now().Add(-20 * time.Millisecond)
			observeReadinessAt(s, base, 1)
			publishReadinessAt(s, base.Add(idle))
			s.BeginPublication()
			s.EndPublication()
			o := s.observation(base.Add(6 * time.Millisecond))
			if o.start != base || o.end != base.Add(idle) || o.generation != 1 {
				t.Fatalf("wrong cap: %+v", o)
			}
			if (o.end.Sub(o.start) >= appLimitedThreshold) != (idle >= appLimitedThreshold) {
				t.Fatal("queued interval affected eligibility")
			}
		})
	}
}
func TestReadinessRejectsOverlappingPublication(t *testing.T) {
	for _, order := range []string{"before-probe", "during-probe", "completed-during-probe"} {
		t.Run(order, func(t *testing.T) {
			s := new(AppLimitedReadiness)
			if order == "before-probe" {
				s.BeginPublication()
			}
			probe := s.BeginProbe()
			if order != "before-probe" {
				s.BeginPublication()
			}
			if order == "completed-during-probe" {
				s.EndPublication()
			}
			s.observeEmpty(probe, 1)
			if !s.observation(monotime.Now()).start.IsZero() {
				t.Fatal("overlapping publication accepted as empty")
			}
			if order != "completed-during-probe" {
				s.EndPublication()
			}
			s.observeEmpty(s.BeginProbe(), 1)
			if s.observation(monotime.Now()).start.IsZero() {
				t.Fatal("fresh empty probe could not arm")
			}
		})
	}
}
func TestReadinessPreservesCompletedLongIdle(t *testing.T) {
	s := new(AppLimitedReadiness)
	base := monotime.Now().Add(-20 * time.Millisecond)
	observeReadinessAt(s, base, 1)
	publishReadinessAt(s, base.Add(3*time.Millisecond))
	s.observeEmpty(s.BeginProbe(), 1)
	o := s.observation(base.Add(time.Second))
	if o.start != base || o.end != base.Add(3*time.Millisecond) {
		t.Fatal("new empty probe erased a qualifying completed interval")
	}
	s.observeEmpty(s.BeginProbe(), 2)
	o = s.observation(base.Add(time.Second))
	if o.generation != 2 || o.end != base.Add(time.Second) {
		t.Fatal("new controller inherited old cap")
	}
}
func TestReadinessDoesNotAccumulateShortIntervals(t *testing.T) {
	s := new(AppLimitedReadiness)
	base := monotime.Now().Add(-20 * time.Millisecond)
	observeReadinessAt(s, base, 1)
	publishReadinessAt(s, base.Add(time.Millisecond))
	s.observeEmpty(s.BeginProbe(), 1)
	o := s.observation(monotime.Now())
	if o.start <= base.Add(time.Millisecond) || s.firstReady != 0 {
		t.Fatal("short separated idle intervals accumulated")
	}
}
func TestReadinessResetPreservesUnfinishedPublishers(t *testing.T) {
	s := new(AppLimitedReadiness)
	s.observeEmpty(s.BeginProbe(), 1)
	s.BeginPublication()
	s.reset()
	s.observeEmpty(s.BeginProbe(), 2)
	if !s.observation(monotime.Now()).start.IsZero() {
		t.Fatal("reset forgot active publisher")
	}
	s.EndPublication()
	s.observeEmpty(s.BeginProbe(), 2)
	if s.observation(monotime.Now()).start.IsZero() {
		t.Fatal("completion prevented a fresh epoch")
	}
}
func TestReadinessConcurrentPublication(t *testing.T) {
	s := new(AppLimitedReadiness)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				s.BeginPublication()
				s.EndPublication()
			}
		}()
	}
	for i := 0; i < 1000; i++ {
		s.observeEmpty(s.BeginProbe(), 1)
		s.observation(monotime.Now())
		s.reset()
	}
	wg.Wait()
	s.observeEmpty(s.BeginProbe(), 2)
	if s.observation(monotime.Now()).start.IsZero() {
		t.Fatal("publication count did not settle")
	}
}

func TestReadinessOverlappingPublishersAndReset(t *testing.T) {
	s := new(AppLimitedReadiness)
	s.observeEmpty(s.BeginProbe(), 1)
	s.BeginPublication()
	s.BeginPublication()
	s.reset()
	s.EndPublication()
	s.observeEmpty(s.BeginProbe(), 2)
	if !s.observation(monotime.Now()).start.IsZero() {
		t.Fatal("one completed publisher hid the other")
	}
	s.EndPublication()
	s.observeEmpty(s.BeginProbe(), 2)
	if s.observation(monotime.Now()).start.IsZero() {
		t.Fatal("both completed publishers prevented rearming")
	}
}
