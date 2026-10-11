// SPDX-License-Identifier: MPL-2.0

package brain

import (
	"bytes"
	"testing"
	"time"
)

func goodEndpoint() PoolEndpoint {
	return PoolEndpoint{
		ID:        "n1",
		Kind:      "skin",
		URL:       "cdn.example.com:443",
		SNI:       "cdn.example.com",
		ServerPub: bytes.Repeat([]byte{1}, 32),
	}
}

func goodAssignment(now time.Time) Assignment {
	return Assignment{
		User:      "u1",
		IssuedAt:  now.Unix(),
		Endpoints: []PoolEndpoint{goodEndpoint()},
	}
}

// Validate must accept a fresh, well-formed assignment for the expected user and
// reject each way it can be wrong — a valid signature alone is not enough.
func TestAssignmentValidate(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	if err := goodAssignment(now).Validate("u1", now, 0); err != nil {
		t.Fatalf("valid assignment rejected: %v", err)
	}
	// Empty expectedUser skips the user check (host authed out of band).
	if err := goodAssignment(now).Validate("", now, 0); err != nil {
		t.Fatalf("valid assignment (no user check) rejected: %v", err)
	}

	if err := goodAssignment(now).Validate("someone-else", now, 0); err != ErrWrongUser {
		t.Fatalf("wrong user: want ErrWrongUser, got %v", err)
	}

	stale := goodAssignment(now.Add(-MaxAssignmentAge - time.Hour))
	if err := stale.Validate("u1", now, 0); err != ErrStale {
		t.Fatalf("stale: want ErrStale, got %v", err)
	}

	future := goodAssignment(now.Add(time.Hour))
	if err := future.Validate("u1", now, 0); err != ErrFromFuture {
		t.Fatalf("future: want ErrFromFuture, got %v", err)
	}

	empty := goodAssignment(now)
	empty.Endpoints = nil
	if err := empty.Validate("u1", now, 0); err != ErrNoEndpoints {
		t.Fatalf("no endpoints: want ErrNoEndpoints, got %v", err)
	}

	badEP := goodAssignment(now)
	badEP.Endpoints[0].ServerPub = []byte{1, 2, 3} // not 32 bytes
	if err := badEP.Validate("u1", now, 0); err == nil {
		t.Fatal("endpoint with short server_pub should fail validation")
	}
}

// PoolEndpoint.Valid rejects the concrete ways an endpoint can be unusable.
func TestPoolEndpointValid(t *testing.T) {
	if err := goodEndpoint().Valid(); err != nil {
		t.Fatalf("good endpoint rejected: %v", err)
	}
	cases := map[string]func(*PoolEndpoint){
		"no id":     func(e *PoolEndpoint) { e.ID = "" },
		"bad kind":  func(e *PoolEndpoint) { e.Kind = "wormhole" },
		"no url":    func(e *PoolEndpoint) { e.URL = "" },
		"short pub": func(e *PoolEndpoint) { e.ServerPub = []byte{1} },
		"nil pub":   func(e *PoolEndpoint) { e.ServerPub = nil },
	}
	for name, mangle := range cases {
		ep := goodEndpoint()
		mangle(&ep)
		if err := ep.Valid(); err == nil {
			t.Errorf("%s: expected Valid() to fail", name)
		}
	}
}
