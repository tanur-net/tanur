// SPDX-License-Identifier: MPL-2.0

package brain

import (
	"context"
	"errors"
	"io"
	"sync"
	"syscall"
	"testing"
	"time"
)

// fakeConn is a throwaway stream for successful dials.
type fakeConn struct{ io.ReadWriteCloser }

func okDial(id string, calls *[]string, mu *sync.Mutex) func(context.Context) (io.ReadWriteCloser, error) {
	return func(context.Context) (io.ReadWriteCloser, error) {
		mu.Lock()
		*calls = append(*calls, id)
		mu.Unlock()
		return fakeConn{}, nil
	}
}

func failDial(id string, calls *[]string, mu *sync.Mutex) func(context.Context) (io.ReadWriteCloser, error) {
	return func(context.Context) (io.ReadWriteCloser, error) {
		mu.Lock()
		*calls = append(*calls, id)
		mu.Unlock()
		return nil, errors.New("down")
	}
}

// A staged dial failure must surface its phase to Report (for telemetry), while
// a successful dial reports an empty stage.
func TestDialReportsStage(t *testing.T) {
	stagedDial := func(stage string) func(context.Context) (io.ReadWriteCloser, error) {
		return func(context.Context) (io.ReadWriteCloser, error) {
			// A real connection-reset so ReasonOf classifies via errors.Is, the
			// path production hits — not a string match.
			return nil, Staged(stage, syscall.ECONNRESET)
		}
	}
	l := New([]Endpoint{
		{ID: "a", Priority: 0, Dial: stagedDial("tls")},
		{ID: "b", Priority: 1, Dial: func(context.Context) (io.ReadWriteCloser, error) { return fakeConn{}, nil }},
	}, time.Minute)

	got := map[string]string{}
	gotReason := map[string]string{}
	l.Report = func(networkKey, epID string, ok, control bool, stage, reason string) {
		got[epID] = stage
		gotReason[epID] = reason
	}
	if _, _, err := l.Dial(context.Background(), "mci"); err != nil {
		t.Fatal(err)
	}
	if got["a"] != "tls" {
		t.Fatalf("failed endpoint 'a' should report stage 'tls', got %q", got["a"])
	}
	if gotReason["a"] != "reset" {
		t.Fatalf("failed endpoint 'a' should report reason 'reset', got %q", gotReason["a"])
	}
	if got["b"] != "" || gotReason["b"] != "" {
		t.Fatalf("successful endpoint 'b' should report empty stage/reason, got %q/%q", got["b"], gotReason["b"])
	}
}

func TestDialTriesPriorityOrder(t *testing.T) {
	var calls []string
	var mu sync.Mutex
	l := New([]Endpoint{
		{ID: "direct", Priority: 9, Dial: okDial("direct", &calls, &mu)},
		{ID: "gcore", Priority: 0, Dial: okDial("gcore", &calls, &mu)},
		{ID: "skin", Priority: 5, Dial: okDial("skin", &calls, &mu)},
	}, time.Minute)

	_, id, err := l.Dial(context.Background(), "mci")
	if err != nil {
		t.Fatal(err)
	}
	if id != "gcore" {
		t.Fatalf("expected lowest-priority 'gcore' first, got %q", id)
	}
	if len(calls) != 1 || calls[0] != "gcore" {
		t.Fatalf("expected only gcore dialed, got %v", calls)
	}
}

func TestDialFallsBackOnFailure(t *testing.T) {
	var calls []string
	var mu sync.Mutex
	l := New([]Endpoint{
		{ID: "gcore", Priority: 0, Dial: failDial("gcore", &calls, &mu)},
		{ID: "cf", Priority: 1, Dial: failDial("cf", &calls, &mu)},
		{ID: "skin", Priority: 2, Dial: okDial("skin", &calls, &mu)},
	}, time.Minute)

	_, id, err := l.Dial(context.Background(), "mci")
	if err != nil {
		t.Fatal(err)
	}
	if id != "skin" {
		t.Fatalf("expected fallback to skin, got %q", id)
	}
	if len(calls) != 3 {
		t.Fatalf("expected all three tried in order, got %v", calls)
	}
}

func TestRemembersLastGoodPerNetwork(t *testing.T) {
	var calls []string
	var mu sync.Mutex
	l := New([]Endpoint{
		{ID: "gcore", Priority: 0, Dial: failDial("gcore", &calls, &mu)},
		{ID: "skin", Priority: 5, Dial: okDial("skin", &calls, &mu)},
	}, time.Minute)

	// First dial on mci: gcore fails, skin works.
	l.Dial(context.Background(), "mci")
	if l.LastGood("mci") != "skin" {
		t.Fatalf("expected lastGood=skin, got %q", l.LastGood("mci"))
	}
	// Second dial on mci: skin should be tried FIRST now (gcore still cooled).
	calls = nil
	_, id, _ := l.Dial(context.Background(), "mci")
	if id != "skin" || len(calls) != 1 || calls[0] != "skin" {
		t.Fatalf("expected skin tried first from memory, got id=%q calls=%v", id, calls)
	}
}

func TestNetworksAreIndependent(t *testing.T) {
	var calls []string
	var mu sync.Mutex
	l := New([]Endpoint{
		{ID: "gcore", Priority: 0, Dial: okDial("gcore", &calls, &mu)},
		{ID: "skin", Priority: 5, Dial: okDial("skin", &calls, &mu)},
	}, time.Minute)

	// Force irancell to remember skin by failing gcore only for it.
	l.recordFailure("irancell", "gcore")
	l.recordSuccess("irancell", "skin")

	// mci has no memory: should still try gcore first.
	_, id, _ := l.Dial(context.Background(), "mci")
	if id != "gcore" {
		t.Fatalf("mci should be unaffected by irancell memory, got %q", id)
	}
	if l.LastGood("irancell") != "skin" {
		t.Fatalf("irancell memory leaked")
	}
}

func TestPenaltyBoxExpires(t *testing.T) {
	var calls []string
	var mu sync.Mutex
	now := time.Unix(1000, 0)
	l := New([]Endpoint{
		{ID: "gcore", Priority: 0, Dial: failDial("gcore", &calls, &mu)},
		{ID: "skin", Priority: 5, Dial: okDial("skin", &calls, &mu)},
	}, 3*time.Minute)
	l.clock = func() time.Time { return now }

	// gcore fails -> penalty for 3 min; skin works.
	l.Dial(context.Background(), "mci")
	// Make gcore succeed now, but it is still cooled down -> should be skipped.
	gcoreCalls := 0
	l.mu.Lock()
	l.eps[0].Dial = func(context.Context) (io.ReadWriteCloser, error) { gcoreCalls++; return fakeConn{}, nil }
	l.mu.Unlock()

	now = now.Add(1 * time.Minute) // still within cooldown
	_, id, _ := l.Dial(context.Background(), "mci")
	if id != "skin" || gcoreCalls != 0 {
		t.Fatalf("gcore should be in penalty box; id=%q gcoreCalls=%d", id, gcoreCalls)
	}

	now = now.Add(3 * time.Minute) // cooldown expired
	_, id, _ = l.Dial(context.Background(), "mci")
	if id != "gcore" || gcoreCalls != 1 {
		t.Fatalf("gcore should be retried after cooldown; id=%q gcoreCalls=%d", id, gcoreCalls)
	}
}

func TestAllFailed(t *testing.T) {
	var calls []string
	var mu sync.Mutex
	l := New([]Endpoint{
		{ID: "a", Priority: 0, Dial: failDial("a", &calls, &mu)},
		{ID: "b", Priority: 1, Dial: failDial("b", &calls, &mu)},
	}, time.Minute)
	if _, _, err := l.Dial(context.Background(), "mci"); err != ErrAllFailed {
		t.Fatalf("expected ErrAllFailed, got %v", err)
	}
}

// Even when every endpoint is cooled down, Dial must still try (never give up).
func TestTriesEvenWhenAllCooled(t *testing.T) {
	var calls []string
	var mu sync.Mutex
	now := time.Unix(5000, 0)
	l := New([]Endpoint{
		{ID: "a", Priority: 0, Dial: okDial("a", &calls, &mu)},
	}, time.Hour)
	l.clock = func() time.Time { return now }
	l.recordFailure("mci", "a") // a is cooled for an hour

	_, id, err := l.Dial(context.Background(), "mci")
	if err != nil || id != "a" {
		t.Fatalf("should still try the only endpoint even if cooled; id=%q err=%v", id, err)
	}
}
