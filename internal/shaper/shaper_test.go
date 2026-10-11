// SPDX-License-Identifier: MPL-2.0

package shaper

import (
	"bytes"
	"testing"
	"time"

	"github.com/tanur-net/tanur/recipe"
)

func testRecipe() recipe.Recipe {
	return recipe.Recipe{
		ID:      "t",
		Version: 1,
		Skin:    recipe.SkinParams{ServerName: "example.com", ALPN: []string{"http/1.1"}},
		Frame:   recipe.IntDist{Min: 100, Max: 1400},
		Burst:   recipe.IntDist{Min: 8, Max: 64},
		Gap:     recipe.IntDist{Min: 5, Max: 30},
		Pause:   recipe.IntDist{Min: 0, Max: 40},
		Pad:     recipe.IntDist{Min: 0, Max: 256},
		Session: recipe.SessionBounds{MaxSeconds: 600, MaxBytes: 1 << 20},
	}
}

func nonce(b byte) []byte { return bytes.Repeat([]byte{b}, recipe.NonceLen) }

func TestOpeningWindowCapsEarlyFrames(t *testing.T) {
	r := testRecipe()
	r.Open = recipe.OpenParams{Frames: 6, Cap: 80} // first 6 frames <= 80 wire bytes
	sh, err := New(r, nonce(9))
	if err != nil {
		t.Fatal(err)
	}
	// The first 6 frames must each stay within the cap even though the caller has
	// plenty of data ready (want large).
	for i := 0; i < 6; i++ {
		step, err := sh.Next(10000)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if step.Wire() > 80 {
			t.Fatalf("opening frame %d exceeded cap: wire=%d", i, step.Wire())
		}
	}
	// After the window, at least one of the next frames should exceed the cap —
	// i.e. the session "opens up" to normal sizes.
	opened := false
	for i := 0; i < 20; i++ {
		step, err := sh.Next(10000)
		if err != nil {
			t.Fatal(err)
		}
		if step.Wire() > 80 {
			opened = true
			break
		}
	}
	if !opened {
		t.Fatal("session never opened up past the opening cap")
	}
}

func TestNoOpeningWindowByDefault(t *testing.T) {
	// With the zero-value Open, behaviour is unchanged: a large frame can appear
	// immediately.
	sh, _ := New(testRecipe(), nonce(3))
	big := false
	for i := 0; i < 50; i++ {
		step, _ := sh.Next(10000)
		if step.Wire() > 80 {
			big = true
			break
		}
	}
	if !big {
		t.Fatal("without an opening window, early frames should not be capped small")
	}
}

func TestNewRejectsBadRecipe(t *testing.T) {
	bad := testRecipe()
	bad.Session.MaxBytes = 0
	if _, err := New(bad, nonce(1)); err == nil {
		t.Fatal("expected invalid recipe to be rejected")
	}
}

func TestStepRespectsFrameAndWant(t *testing.T) {
	sh, err := New(testRecipe(), nonce(9))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 500; i++ {
		st, err := sh.Next(50)
		if err != nil {
			break
		}
		if st.Payload > 50 {
			t.Fatalf("payload %d exceeds want 50", st.Payload)
		}
		if st.Payload < 0 || st.Pad < 0 || st.PauseMS < 0 {
			t.Fatalf("negative field in step %+v", st)
		}
		if st.Pad > 256 || st.PauseMS > 40 {
			t.Fatalf("step out of recipe bounds: %+v", st)
		}
	}
}

// Frames inside a burst carry no pause; the gap appears only at burst starts.
// This is the property that both looks like streaming and keeps throughput up.
func TestBurstStructure(t *testing.T) {
	r := testRecipe()
	r.Burst = recipe.IntDist{Min: 5, Max: 5} // exactly 5 frames per burst
	r.Gap = recipe.IntDist{Min: 10, Max: 10} // exactly 10ms between bursts
	r.Pause = recipe.IntDist{Min: 0, Max: 0} // no intra-burst jitter
	sh, err := New(r, nonce(4))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		st, err := sh.Next(100)
		if err != nil {
			t.Fatal(err)
		}
		wantPause := 0
		if i%5 == 0 { // first frame of each burst of 5
			wantPause = 10
		}
		if st.PauseMS != wantPause {
			t.Fatalf("frame %d: pause=%d want %d (burst boundaries carry the gap)", i, st.PauseMS, wantPause)
		}
	}
}

func TestIdleFrameCarriesOnlyPadding(t *testing.T) {
	sh, _ := New(testRecipe(), nonce(3))
	st, err := sh.Next(0)
	if err != nil {
		t.Fatal(err)
	}
	if st.Payload != 0 {
		t.Fatalf("idle frame should carry no payload, got %d", st.Payload)
	}
	// It may still carry padding so silence does not stand out.
	if st.Wire() != st.Pad {
		t.Fatalf("idle wire bytes should equal padding: %+v", st)
	}
}

// The session must terminate at its byte bound rather than run forever.
func TestSessionByteBoundEnforced(t *testing.T) {
	r := testRecipe()
	r.Session.MaxBytes = 5000
	sh, _ := New(r, nonce(7))
	total := 0
	hit := false
	for i := 0; i < 100000; i++ {
		st, err := sh.Next(1400)
		if err == ErrSessionExhausted {
			hit = true
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		total += st.Wire()
	}
	if !hit {
		t.Fatal("session never hit its byte bound")
	}
	// The frame is clamped to the remaining budget, so the session never puts
	// more than MaxBytes on the wire — not even by one frame.
	if int64(total) > r.Session.MaxBytes {
		t.Fatalf("overran byte bound: %d vs %d", total, r.Session.MaxBytes)
	}
}

func TestSessionTimeBoundEnforced(t *testing.T) {
	r := testRecipe()
	r.Session.MaxSeconds = 1     // 1 second of REAL time
	r.Session.MaxBytes = 1 << 30 // make bytes effectively unlimited
	sh, _ := New(r, nonce(5))

	// Inject a controllable clock: wall-clock only moves when we move it, so the
	// bound is real time, not the sum of planned pauses (which a fast link never
	// accumulates). This is the regression test for that distinction.
	cur := time.Unix(1_000_000, 0)
	sh.now = func() time.Time { return cur }

	// Many frames back-to-back with no real time elapsed must NOT exhaust.
	for i := 0; i < 10000; i++ {
		if _, err := sh.Next(10); err != nil {
			t.Fatalf("no real time passed, frame %d should succeed, got %v", i, err)
		}
	}
	// Once real time crosses MaxSeconds, the very next frame is refused.
	cur = cur.Add(1100 * time.Millisecond)
	if _, err := sh.Next(10); err != ErrSessionExhausted {
		t.Fatalf("after %ds of wall-clock, want ErrSessionExhausted, got %v", r.Session.MaxSeconds, err)
	}
}

// Same nonce and recipe must reproduce the exact plan (needed for tests and for
// the two ends to agree where required).
func TestPlanDeterministic(t *testing.T) {
	a, _ := New(testRecipe(), nonce(2))
	b, _ := New(testRecipe(), nonce(2))
	for i := 0; i < 1000; i++ {
		sa, ea := a.Next(200)
		sb, eb := b.Next(200)
		if (ea == nil) != (eb == nil) {
			t.Fatalf("step %d: error mismatch %v vs %v", i, ea, eb)
		}
		if ea != nil {
			break
		}
		if sa != sb {
			t.Fatalf("step %d differs: %+v vs %+v", i, sa, sb)
		}
	}
}
