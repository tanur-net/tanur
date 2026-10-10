// SPDX-License-Identifier: MPL-2.0

// Package brain is the client-side decision layer: given several ways to reach
// the service (CDN-A, CDN-B, TLS skin, direct), it picks which to try, in what
// order, learns per operator what works, and keeps a failed path in a "penalty
// box" so it is not retried for a while.
//
// This is the lever that gives durability: no single carrier stays open forever
// (even a CDN gets throttled), so the client must ladder across many and
// remember, per network, what is working right now. Server-pushed tactics and
// per-user host subsets plug in by changing the endpoint list; this package is
// the selection logic. (docs/dpi-and-shaper-requirements S7, S8; ROADMAP phase 3)
package brain

import (
	"context"
	"errors"
	"io"
	"sort"
	"sync"
	"time"
)

// Endpoint is one way to reach the service. Dial produces a ready stream (in
// production: carrier dial + inner handshake + a liveness check); an error means
// this path is not working right now.
type Endpoint struct {
	// ID is stable and unique (e.g. "gcore-01", "skin-nbg-7").
	ID string
	// Label groups endpoints by kind/CDN for telemetry ("gcore", "cloudflare",
	// "skin", "direct").
	Label string
	// Priority orders endpoints by preference; lower is tried first. Put the
	// durable, origin-hiding carriers (CDN) low and direct high (last resort).
	Priority int
	// Dial opens the path. It must respect ctx cancellation.
	Dial func(ctx context.Context) (io.ReadWriteCloser, error)
}

// ErrAllFailed is returned when every endpoint failed in one Dial call.
var ErrAllFailed = errors.New("brain: all endpoints failed")

// Ladder selects among endpoints with per-network memory and a penalty box.
type Ladder struct {
	cooldown time.Duration
	clock    func() time.Time

	// Report, if set, is called once per Dial for each endpoint tried, with the
	// per-attempt outcome and whether the line was up at all (control = any
	// endpoint in that Dial worked). The engine wires this to telemetry.
	Report func(networkKey, epID string, ok, control bool)

	mu       sync.Mutex
	eps      []Endpoint
	lastGood map[string]string    // networkKey -> endpoint ID that last worked
	penalty  map[string]time.Time // networkKey|epID -> retry-not-before
}

// New builds a Ladder. cooldown is how long a failed endpoint is skipped for a
// network (research: a penalty box of at least a few minutes). A nil clock uses
// time.Now.
func New(eps []Endpoint, cooldown time.Duration) *Ladder {
	cp := append([]Endpoint(nil), eps...)
	sort.SliceStable(cp, func(i, j int) bool { return cp[i].Priority < cp[j].Priority })
	return &Ladder{
		cooldown: cooldown,
		clock:    time.Now,
		eps:      cp,
		lastGood: map[string]string{},
		penalty:  map[string]time.Time{},
	}
}

// Dial tries endpoints for the given network until one works, and records the
// outcome. networkKey identifies the vantage (e.g. operator MCC/MNC or BSSID) so
// memory and penalties are per network. It returns the live stream and the id of
// the endpoint that worked.
func (l *Ladder) Dial(ctx context.Context, networkKey string) (io.ReadWriteCloser, string, error) {
	type attempt struct {
		id string
		ok bool
	}
	var attempts []attempt
	var result io.ReadWriteCloser
	var resultID string
	rerr := error(ErrAllFailed)

	for _, ep := range l.order(networkKey) {
		if ctx.Err() != nil {
			rerr = ctx.Err()
			break
		}
		conn, err := ep.Dial(ctx)
		if err == nil {
			l.recordSuccess(networkKey, ep.ID)
			attempts = append(attempts, attempt{ep.ID, true})
			result, resultID, rerr = conn, ep.ID, nil
			break
		}
		l.recordFailure(networkKey, ep.ID)
		attempts = append(attempts, attempt{ep.ID, false})
	}

	if l.Report != nil {
		control := result != nil // line was up if any endpoint worked
		for _, a := range attempts {
			l.Report(networkKey, a.id, a.ok, control)
		}
	}
	return result, resultID, rerr
}

// order returns the endpoints to try, by priority, with endpoints still in the
// penalty box dropped. Priority + penalty box already gives the behaviour we
// want: the preferred (durable, origin-hiding) carrier is tried first; once it
// fails it is cooled and skipped, so we stick with the next-best fallback; when
// its cooldown expires it rises to the front again and is re-probed. If every
// endpoint is cooled down, it returns all of them so we never give up outright.
func (l *Ladder) order(networkKey string) []Endpoint {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()

	var live []Endpoint
	for _, ep := range l.eps {
		if until, ok := l.penalty[networkKey+"|"+ep.ID]; ok && now.Before(until) {
			continue
		}
		live = append(live, ep)
	}
	if len(live) == 0 {
		return append([]Endpoint(nil), l.eps...)
	}
	return live
}

func (l *Ladder) recordSuccess(networkKey, epID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lastGood[networkKey] = epID
	delete(l.penalty, networkKey+"|"+epID)
}

func (l *Ladder) recordFailure(networkKey, epID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.penalty[networkKey+"|"+epID] = l.clock().Add(l.cooldown)
	if l.lastGood[networkKey] == epID {
		delete(l.lastGood, networkKey) // it was good, now it is not
	}
}

// LastGood reports the endpoint id the ladder would try first for a network, or
// "" if it has no memory yet. Useful for telemetry and tests.
func (l *Ladder) LastGood(networkKey string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastGood[networkKey]
}
