// SPDX-License-Identifier: MPL-2.0

package brain

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Assignment is what a user receives: their per-user subset of endpoints, signed
// so the client can trust it came from our brain and was not injected by a
// censor or a malicious CDN.
type Assignment struct {
	User      string         `json:"user"`
	IssuedAt  int64          `json:"issued_at"`
	Endpoints []PoolEndpoint `json:"endpoints"`
}

// signed wraps the canonical JSON of an Assignment with an Ed25519 signature.
type signed struct {
	Assignment json.RawMessage `json:"assignment"`
	Sig        []byte          `json:"sig"`
}

var (
	// ErrBadSignature is returned when an assignment's signature does not verify.
	ErrBadSignature = errors.New("brain: assignment signature does not verify")
	// ErrBadKey is returned for a public key of the wrong length.
	ErrBadKey = errors.New("brain: public key must be ed25519.PublicKeySize bytes")
	// ErrWrongUser, ErrStale, ErrFromFuture and ErrNoEndpoints are content
	// failures surfaced by Validate (the signature already verified).
	ErrWrongUser   = errors.New("brain: assignment is for a different user")
	ErrStale       = errors.New("brain: assignment is stale")
	ErrFromFuture  = errors.New("brain: assignment issued in the future")
	ErrNoEndpoints = errors.New("brain: assignment has no endpoints")
)

const (
	// MaxAssignmentAge bounds how old a signed assignment may be before a client
	// refuses it, so a captured old assignment cannot be replayed indefinitely.
	MaxAssignmentAge = 48 * time.Hour
	// assignmentSkew tolerates modest client/server clock disagreement for the
	// freshness check.
	assignmentSkew = 10 * time.Minute
)

// OpenAssignment verifies a signed assignment against pub and returns it. The
// client must reject any assignment that does not verify.
func OpenAssignment(data []byte, pub ed25519.PublicKey) (Assignment, error) {
	if len(pub) != ed25519.PublicKeySize {
		return Assignment{}, ErrBadKey
	}
	var s signed
	if err := json.Unmarshal(data, &s); err != nil {
		return Assignment{}, fmt.Errorf("brain: parse envelope: %w", err)
	}
	if !ed25519.Verify(pub, s.Assignment, s.Sig) {
		return Assignment{}, ErrBadSignature
	}
	var a Assignment
	if err := json.Unmarshal(s.Assignment, &a); err != nil {
		return Assignment{}, fmt.Errorf("brain: parse assignment: %w", err)
	}
	return a, nil
}

// Validate checks an opened assignment's CONTENT. OpenAssignment already proved
// the signature (that the brain issued it, untampered); Validate proves it is
// also fresh, meant for this user, and dialable — the three things a valid
// signature does NOT prove on its own. expectedUser == "" skips the user check
// (for a host that authenticated the user out of band). now is injectable for
// tests; maxAge of 0 uses MaxAssignmentAge.
func (a Assignment) Validate(expectedUser string, now time.Time, maxAge time.Duration) error {
	if maxAge <= 0 {
		maxAge = MaxAssignmentAge
	}
	if expectedUser != "" && a.User != expectedUser {
		return ErrWrongUser
	}
	issued := time.Unix(a.IssuedAt, 0)
	if now.Sub(issued) > maxAge {
		return ErrStale
	}
	if issued.Sub(now) > assignmentSkew {
		return ErrFromFuture
	}
	if len(a.Endpoints) == 0 {
		return ErrNoEndpoints
	}
	for _, ep := range a.Endpoints {
		if err := ep.Valid(); err != nil {
			return err
		}
	}
	return nil
}

// FetchAssignment gets and verifies a user's assignment from rawURL. rawURL
// should already carry the fronting; this adds the user query parameter with
// the query API so it is always encoded and an existing query is preserved.
func FetchAssignment(client *http.Client, rawURL, user string, pub ed25519.PublicKey) (Assignment, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return Assignment{}, err
	}
	q := u.Query()
	q.Set("user", user)
	u.RawQuery = q.Encode()
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return Assignment{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return Assignment{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Assignment{}, fmt.Errorf("brain: assign http %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Assignment{}, err
	}
	return OpenAssignment(data, pub)
}
