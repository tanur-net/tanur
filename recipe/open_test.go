// SPDX-License-Identifier: MPL-2.0

package recipe

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
)

// signDirect mirrors what the brain's Seal does, but inline, so these client-side
// Open tests do not depend on the (server-side) Seal.
func signDirect(t *testing.T, r Recipe, priv ed25519.PrivateKey) []byte {
	t.Helper()
	body, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(Signed{Recipe: body, Sig: ed25519.Sign(priv, body)})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestOpenAcceptsValidSigned(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	in := validRecipe()
	out, err := Open(signDirect(t, in, priv), pub)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if out.ID != in.ID || out.Skin.ServerName != in.Skin.ServerName {
		t.Fatalf("Open changed recipe: %+v", out)
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Open(signDirect(t, validRecipe(), priv), otherPub); err != ErrBadSignature {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

func TestOpenRejectsTamperedRecipe(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	data := signDirect(t, validRecipe(), priv)
	var s Signed
	_ = json.Unmarshal(data, &s)
	var r Recipe
	_ = json.Unmarshal(s.Recipe, &r)
	r.Skin.ServerName = "attacker.example" // a censor swapping the skin domain
	s.Recipe, _ = json.Marshal(r)
	tampered, _ := json.Marshal(s)
	if _, err := Open(tampered, pub); err != ErrBadSignature {
		t.Fatalf("expected tampered recipe to fail with ErrBadSignature, got %v", err)
	}
}

func TestOpenRejectsInvalidRecipeEvenIfSigned(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	// Sign a structurally invalid recipe directly to prove Open independently
	// re-validates shape (not just the signature).
	bad := validRecipe()
	bad.Session.MaxBytes = 0 // unbounded: must be rejected
	body, _ := json.Marshal(bad)
	data, _ := json.Marshal(Signed{Recipe: body, Sig: ed25519.Sign(priv, body)})
	if _, err := Open(data, pub); err != ErrUnbounded {
		t.Fatalf("expected ErrUnbounded, got %v", err)
	}
}

func TestOpenRejectsShortKey(t *testing.T) {
	if _, err := Open([]byte(`{}`), ed25519.PublicKey{1, 2, 3}); err != ErrBadKey {
		t.Fatalf("expected ErrBadKey, got %v", err)
	}
}
