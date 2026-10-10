// SPDX-License-Identifier: MPL-2.0

// Package shaper turns a recipe plus a per-session nonce into the concrete
// sequence of frame sizes, pauses and padding that one session will use.
//
// The shaper is deliberately a pure planner: it decides "how big is the next
// frame, how long to wait, how much padding" and nothing about sockets or
// crypto. That keeps it fully testable offline and keeps the wire code thin.
// Design: docs/inner-protocol-v0.md sections 1 and 6.
package shaper

import (
	"errors"

	"github.com/tanur-net/tanur/recipe"
)

// Shaper plans one session's observable behaviour. It enforces the recipe's
// session bounds so a session can never become an unbounded symmetric tunnel.
type Shaper struct {
	r         recipe.Recipe
	s         *recipe.Sampler
	sentB     int64 // bytes accounted so far (payload + padding)
	elapsed   int   // conceptual ms accounted via pauses so far
	burstLeft int   // frames remaining in the current burst
	framesOut int   // frames planned so far (for the opening window)
}

// ErrSessionExhausted is returned when the session's byte or time bound is hit.
// The caller must then tear the session down and dial a fresh one.
var ErrSessionExhausted = errors.New("shaper: session bound reached")

// New builds a shaper for one session. The nonce must be 32 bytes; it seeds the
// sampler so the plan is unpredictable to an observer yet reproducible for tests.
func New(r recipe.Recipe, nonce []byte) (*Shaper, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	s, err := recipe.NewSampler(nonce)
	if err != nil {
		return nil, err
	}
	return &Shaper{r: r, s: s}, nil
}

// Step is the plan for writing one frame.
type Step struct {
	// Payload is how many bytes of real data this frame should carry at most.
	Payload int
	// Pad is how many padding bytes to append so the frame length on the wire
	// does not reveal the payload length.
	Pad int
	// PauseMS is how long to wait before sending this frame.
	PauseMS int
}

// Wire is the total bytes this step puts on the wire.
func (s Step) Wire() int { return s.Payload + s.Pad }

// Next returns the plan for the next frame given how many real payload bytes the
// caller has ready (want). The returned Payload is min(want, sampled frame
// size). It returns ErrSessionExhausted once a bound is reached.
//
// want <= 0 is allowed and yields a keepalive-style frame carrying only padding,
// so idle periods still look like ordinary traffic rather than silence.
func (s *Shaper) Next(want int) (Step, error) {
	if s.sentB >= s.r.Session.MaxBytes {
		return Step{}, ErrSessionExhausted
	}
	if s.elapsed >= s.r.Session.MaxSeconds*1000 {
		return Step{}, ErrSessionExhausted
	}

	// Pacing: a gap only at the START of a new burst; within a burst, frames go
	// back-to-back (optionally with tiny per-frame jitter). This is what makes
	// the flow look like chunked streaming rather than a steady tunnel, and what
	// keeps throughput from collapsing under per-frame pauses on a slow link.
	var pause int
	if s.burstLeft <= 0 {
		s.burstLeft = s.s.Int(s.r.Burst) // start a new burst
		pause = s.s.Int(s.r.Gap)         // the inter-burst gap
	} else {
		pause = s.s.Int(s.r.Pause) // intra-burst jitter, usually 0
	}
	s.burstLeft--

	frame := s.s.Int(s.r.Frame)
	// Opening window: for the first Open.Frames frames, hold the frame size at or
	// below Open.Cap so the early upstream is a few small packets, not an instant
	// bulk burst that trips the operator's initial-upload limit. Sampling happens
	// first (then we clamp), so determinism of later frames is unchanged.
	opening := s.framesOut < s.r.Open.Frames
	if opening && frame > s.r.Open.Cap {
		frame = s.r.Open.Cap
	}

	payload := 0
	if want > 0 {
		payload = want
		if payload > frame {
			payload = frame
		}
	}
	pad := s.s.Int(s.r.Pad)
	if opening && payload+pad > s.r.Open.Cap {
		pad = s.r.Open.Cap - payload
		if pad < 0 {
			pad = 0
		}
	}
	s.framesOut++

	// Account against the session bounds before returning, so the caller cannot
	// overrun them by ignoring the error on a later call.
	s.sentB += int64(payload + pad)
	s.elapsed += pause

	return Step{Payload: payload, Pad: pad, PauseMS: pause}, nil
}

// Remaining reports the byte budget left in the session.
func (s *Shaper) Remaining() int64 {
	rem := s.r.Session.MaxBytes - s.sentB
	if rem < 0 {
		return 0
	}
	return rem
}
