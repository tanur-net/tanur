// SPDX-License-Identifier: MPL-2.0

package recipe

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
)

// A recipe reaches a client signed. The client must reject any recipe whose
// signature does not verify against a public key baked into the build, so a
// censor or a malicious host cannot inject a recipe that weakens the client
// (e.g. one that downgrades the skin or leaks a fixed constant). Signing keys
// live with the brain, never in the client or this package.

// Signed wraps a recipe with a detached Ed25519 signature over its canonical
// JSON encoding.
type Signed struct {
	// Recipe is the raw canonical JSON of the Recipe (not re-marshaled on
	// verify, so the exact signed bytes are checked).
	Recipe json.RawMessage `json:"recipe"`
	// Sig is the Ed25519 signature over Recipe's bytes.
	Sig []byte `json:"sig"`
}

var (
	// ErrBadSignature is returned when a recipe's signature does not verify.
	ErrBadSignature = errors.New("recipe: signature does not verify")
	// ErrBadKey is returned for a public key of the wrong length.
	ErrBadKey = errors.New("recipe: public key must be ed25519.PublicKeySize bytes")
)

// Open verifies a signed recipe against pub, then parses and validates it. It
// returns the recipe only when the signature verifies AND Validate passes, so a
// caller that uses the result can trust both its origin and its shape.
func Open(data []byte, pub ed25519.PublicKey) (Recipe, error) {
	if len(pub) != ed25519.PublicKeySize {
		return Recipe{}, ErrBadKey
	}
	var s Signed
	if err := json.Unmarshal(data, &s); err != nil {
		return Recipe{}, fmt.Errorf("recipe: cannot parse envelope: %w", err)
	}
	if !ed25519.Verify(pub, s.Recipe, s.Sig) {
		return Recipe{}, ErrBadSignature
	}
	var r Recipe
	if err := json.Unmarshal(s.Recipe, &r); err != nil {
		return Recipe{}, fmt.Errorf("recipe: cannot parse recipe: %w", err)
	}
	if err := r.Validate(); err != nil {
		return Recipe{}, err
	}
	return r, nil
}
