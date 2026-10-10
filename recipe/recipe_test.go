// SPDX-License-Identifier: MPL-2.0

package recipe

import (
	"bytes"
	"testing"
)

func validRecipe() Recipe {
	return Recipe{
		ID:      "v0-sample",
		Version: 1,
		Skin: SkinParams{
			ServerName:    "example.com",
			ClientHelloID: "chrome-latest",
			Path:          "/",
			ALPN:          []string{"http/1.1"},
		},
		Frame:   IntDist{Min: 100, Max: 1400},
		Burst:   IntDist{Min: 8, Max: 64},
		Gap:     IntDist{Min: 5, Max: 30},
		Pause:   IntDist{Min: 0, Max: 40},
		Pad:     IntDist{Min: 0, Max: 256},
		Session: SessionBounds{MaxSeconds: 600, MaxBytes: 50 << 20},
	}
}

func TestValidateAcceptsGoodRecipe(t *testing.T) {
	if err := validRecipe().Validate(); err != nil {
		t.Fatalf("valid recipe rejected: %v", err)
	}
}

func TestValidateCatchesProblems(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Recipe)
	}{
		{"no id", func(r *Recipe) { r.ID = "" }},
		{"bad version", func(r *Recipe) { r.Version = 0 }},
		{"no server name", func(r *Recipe) { r.Skin.ServerName = "" }},
		{"no alpn", func(r *Recipe) { r.Skin.ALPN = nil }},
		{"frame min zero", func(r *Recipe) { r.Frame.Min = 0 }},
		{"frame inverted", func(r *Recipe) { r.Frame = IntDist{Min: 10, Max: 5} }},
		{"burst min zero", func(r *Recipe) { r.Burst.Min = 0 }},
		{"unbounded seconds", func(r *Recipe) { r.Session.MaxSeconds = 0 }},
		{"unbounded bytes", func(r *Recipe) { r.Session.MaxBytes = 0 }},
		{"negative open frames", func(r *Recipe) { r.Open = OpenParams{Frames: -1} }},
		{"open frames without cap", func(r *Recipe) { r.Open = OpenParams{Frames: 6, Cap: 0} }},
		{"bad ech base64", func(r *Recipe) { r.Skin.ECHConfigList = "not!base64!" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := validRecipe()
			c.mutate(&r)
			if err := r.Validate(); err == nil {
				t.Fatalf("expected %q to be rejected, but Validate passed", c.name)
			}
		})
	}
}

func TestValidateAcceptsOpenWindowAndECH(t *testing.T) {
	r := validRecipe()
	r.Open = OpenParams{Frames: 6, Cap: 80}
	r.Skin.ECHConfigList = "QUJDRA==" // valid base64 ("ABCD"); shape, not a live ECH key
	if err := r.Validate(); err != nil {
		t.Fatalf("recipe with opening window + ECH rejected: %v", err)
	}
}

func TestSamplerNeeds32ByteNonce(t *testing.T) {
	if _, err := NewSampler(make([]byte, 16)); err == nil {
		t.Fatal("expected short nonce to be rejected")
	}
	if _, err := NewSampler(make([]byte, NonceLen)); err != nil {
		t.Fatalf("32-byte nonce rejected: %v", err)
	}
}

// Same nonce must reproduce the same sequence; this is what makes behaviour
// testable and keeps the two ends in agreement.
func TestSamplerDeterministicForSameNonce(t *testing.T) {
	nonce := bytes.Repeat([]byte{7}, NonceLen)
	dist := IntDist{Min: 100, Max: 1400}

	s1, _ := NewSampler(nonce)
	s2, _ := NewSampler(nonce)
	for i := 0; i < 1000; i++ {
		if a, b := s1.Int(dist), s2.Int(dist); a != b {
			t.Fatalf("draw %d differs: %d vs %d", i, a, b)
		}
	}
}

// Different nonces must (almost surely) diverge, so two sessions of the same
// recipe do not share a fixed size sequence.
func TestSamplerDivergesForDifferentNonce(t *testing.T) {
	dist := IntDist{Min: 0, Max: 1 << 20}
	s1, _ := NewSampler(bytes.Repeat([]byte{1}, NonceLen))
	s2, _ := NewSampler(bytes.Repeat([]byte{2}, NonceLen))
	same := 0
	for i := 0; i < 64; i++ {
		if s1.Int(dist) == s2.Int(dist) {
			same++
		}
	}
	if same > 4 {
		t.Fatalf("two nonces produced %d/64 identical draws; sequences not independent", same)
	}
}

func TestSamplerRespectsBounds(t *testing.T) {
	nonce := bytes.Repeat([]byte{3}, NonceLen)
	s, _ := NewSampler(nonce)
	dist := IntDist{Min: 100, Max: 103}
	seen := map[int]bool{}
	for i := 0; i < 5000; i++ {
		v := s.Int(dist)
		if v < dist.Min || v > dist.Max {
			t.Fatalf("draw %d out of bounds [%d,%d]", v, dist.Min, dist.Max)
		}
		seen[v] = true
	}
	// Over 5000 draws across 4 values, every value should appear.
	for v := dist.Min; v <= dist.Max; v++ {
		if !seen[v] {
			t.Fatalf("value %d never drawn in 5000 samples; sampler not covering range", v)
		}
	}
}

func TestSpan(t *testing.T) {
	if got := (IntDist{Min: 5, Max: 5}).Span(); got != 1 {
		t.Fatalf("single-value span = %d, want 1", got)
	}
	if got := (IntDist{Min: 0, Max: 9}).Span(); got != 10 {
		t.Fatalf("span = %d, want 10", got)
	}
}
