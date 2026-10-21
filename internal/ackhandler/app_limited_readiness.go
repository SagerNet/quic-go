package ackhandler

import (
	"sync"

	"github.com/sagernet/quic-go/internal/monotime"
)

// AppLimitedReadiness coordinates application-data publication with an empty
// packet-packer observation. Its methods never call congestion or queue code.
// Queue publishers must bracket visibility and activation with BeginPublication
// and EndPublication, without holding this mutex across either operation.
// The connection loop alone observes emptiness, consumes evidence, and resets it.
type AppLimitedReadiness struct {
	mutex      sync.Mutex
	serial     uint64
	publishers uint64
	start      monotime.Time
	firstReady monotime.Time
	generation uint64
}

// AppLimitedProbe is a token from immediately before an ordinary pack attempt.
// A token cannot establish emptiness if any publication overlaps the attempt.
type AppLimitedProbe struct {
	serial uint64
	valid  bool
}

type appLimitedObservation struct {
	start, end monotime.Time
	generation uint64
}

func (s *AppLimitedReadiness) BeginPublication() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.serial++
	s.publishers++
	if !s.start.IsZero() && s.firstReady.IsZero() {
		s.firstReady = monotime.Now()
	}
}

func (s *AppLimitedReadiness) EndPublication() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.publishers == 0 {
		panic("application-data publication not started")
	}
	s.publishers--
}

func (s *AppLimitedReadiness) BeginProbe() AppLimitedProbe {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return AppLimitedProbe{serial: s.serial, valid: s.publishers == 0}
}

// observeEmpty must follow an empty ordinary pack attempt. Keeping a completed
// qualifying interval is important: another empty probe must not erase it before
// its next ack-eliciting packet. Short intervals are never added together.
func (s *AppLimitedReadiness) observeEmpty(probe AppLimitedProbe, generation uint64) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if !probe.valid || probe.serial != s.serial || s.publishers != 0 {
		return
	}
	if !s.start.IsZero() && s.generation == generation {
		if s.firstReady.IsZero() || s.firstReady.Sub(s.start) >= appLimitedThreshold {
			return
		}
	}
	s.start = monotime.Now()
	s.firstReady = 0
	s.generation = generation
}

func (s *AppLimitedReadiness) observation(now monotime.Time) appLimitedObservation {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	end := now
	if !s.firstReady.IsZero() && s.firstReady.Before(end) {
		end = s.firstReady
	}
	return appLimitedObservation{start: s.start, end: end, generation: s.generation}
}

func (s *AppLimitedReadiness) reset() {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.start = 0
	s.firstReady = 0
	// Outstanding publishers and serial are intentionally preserved. Resetting
	// classification evidence cannot make an unfinished publication disappear.
}
