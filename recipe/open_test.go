// SPDX-License-Identifier: MPL-2.0

package recipe

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
)

// signRecipe signs a recipe inline, the way a brain-side Seal would, so these
// verify-side tests do not depend on the signing API (which is withheld from the
// open release). It intentionally does NOT re-validate, so a test can sign a
// deliberately invalid recipe and prove Open re-validates on its own.
func signRecipe(t *testing.T, r Recipe, priv ed25519.PrivateKey) []byte {
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

func TestOpenAcceptsValidSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	in := validRecipe()

	out, err := Open(signRecipe(t, in, priv), pub)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if out.ID != in.ID || out.Skin.ServerName != in.Skin.ServerName {
		t.Fatalf("round trip changed recipe: %+v", out)
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)

	data := signRecipe(t, validRecipe(), priv)
	if _, err := Open(data, otherPub); err != ErrBadSignature {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

func TestOpenRejectsTamperedRecipe(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	data := signRecipe(t, validRecipe(), priv)

	var s Signed
	_ = json.Unmarshal(data, &s)
	// Flip the recipe body after signing: a censor swapping the skin domain.
	var r Recipe
	_ = json.Unmarshal(s.Recipe, &r)
	r.Skin.ServerName = "attacker.example"
	s.Recipe, _ = json.Marshal(r)
	tampered, _ := json.Marshal(s)

	if _, err := Open(tampered, pub); err != ErrBadSignature {
		t.Fatalf("expected tampered recipe to fail with ErrBadSignature, got %v", err)
	}
}

func TestOpenRejectsInvalidRecipeEvenIfSigned(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	// Sign a structurally invalid recipe directly (bypassing Seal's Validate)
	// to prove Open independently re-validates shape.
	bad := validRecipe()
	bad.Session.MaxBytes = 0 // unbounded: must be rejected
	body, _ := json.Marshal(bad)
	s := Signed{Recipe: body, Sig: ed25519.Sign(priv, body)}
	data, _ := json.Marshal(s)

	if _, err := Open(data, pub); err != ErrUnbounded {
		t.Fatalf("expected ErrUnbounded, got %v", err)
	}
}

func TestOpenRejectsShortKey(t *testing.T) {
	if _, err := Open([]byte(`{}`), ed25519.PublicKey{1, 2, 3}); err != ErrBadKey {
		t.Fatalf("expected ErrBadKey, got %v", err)
	}
}
