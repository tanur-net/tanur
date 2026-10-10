// SPDX-License-Identifier: MPL-2.0

package brain

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// This file is the client-side (open) half of assignments: the data shape a
// user receives, and the verification + fetch a client performs. The signing
// side (Sign, AssignServer) is the server's and is withheld from the open
// release — see assign_sign.go. (docs/oss/split-plan.md)

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

// FetchAssignment gets and verifies a user's assignment from url. url should
// already carry the fronting; this adds the user query parameter.
func FetchAssignment(client *http.Client, url, user string, pub ed25519.PublicKey) (Assignment, error) {
	req, err := http.NewRequest("GET", url+"?user="+user, nil)
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
