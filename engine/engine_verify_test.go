// SPDX-License-Identifier: MPL-2.0

package engine

// This test exercises the engine's client-side assignment path: fetch a signed
// endpoint list from AssignURL, verify its Ed25519 signature, and tunnel through
// it. It signs the response inline (the way the private brain would) so it needs
// none of the withheld server-side symbols, and therefore ships in the open
// tree. (docs/oss/split-plan.md)

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tanur-net/tanur/brain"
)

func TestEngineVerifiesSignedAssignment(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "via-verified-assignment")
	}))
	defer target.Close()
	targetHost := strings.TrimPrefix(target.URL, "http://")

	curl, pub, stop := carrierTunnelServer(t)
	defer stop()

	bpub, bpriv, _ := ed25519.GenerateKey(rand.Reader)

	// Serve an assignment signed inline with the same envelope shape the client
	// verifies: {"assignment": <canonical json>, "sig": <ed25519 over that json>}.
	assignSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := brain.Assignment{
			User: r.URL.Query().Get("user"),
			Endpoints: []brain.PoolEndpoint{
				{ID: "cdn-1", Label: "gcore", Kind: "carrier", Priority: 0, URL: curl, ServerPub: pub},
			},
		}
		body, err := json.Marshal(a)
		if err != nil {
			http.Error(w, "marshal", http.StatusInternalServerError)
			return
		}
		env := struct {
			Assignment json.RawMessage `json:"assignment"`
			Sig        []byte          `json:"sig"`
		}{Assignment: body, Sig: ed25519.Sign(bpriv, body)}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(env)
	}))
	defer assignSrv.Close()

	eng, err := New(Config{
		User:      "user-42",
		AssignURL: assignSrv.URL,
		BrainPub:  bpub,
		Recipe:    testRecipe(),
		SocksAddr: "127.0.0.1:0",
		Network:   func() string { return "irancell" },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer eng.Stop()

	body := socksGet(t, eng.Addr(), targetHost, "/")
	if !strings.Contains(body, "via-verified-assignment") {
		t.Fatalf("did not reach target via verified assignment; got %q", body)
	}
}

// A tampered endpoint list (valid JSON, bad signature) must be rejected: the
// engine must refuse to dial endpoints a censor or malicious CDN injected.
func TestEngineRejectsUnsignedAssignment(t *testing.T) {
	bpub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, wrongPriv, _ := ed25519.GenerateKey(rand.Reader)

	assignSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := brain.Assignment{
			User: r.URL.Query().Get("user"),
			Endpoints: []brain.PoolEndpoint{
				{ID: "evil", Label: "direct", Kind: "direct", Priority: 0, URL: "127.0.0.1:1"},
			},
		}
		body, _ := json.Marshal(a)
		env := struct {
			Assignment json.RawMessage `json:"assignment"`
			Sig        []byte          `json:"sig"`
		}{Assignment: body, Sig: ed25519.Sign(wrongPriv, body)} // signed by the WRONG key
		_ = json.NewEncoder(w).Encode(env)
	}))
	defer assignSrv.Close()

	eng, err := New(Config{
		User:      "user-42",
		AssignURL: assignSrv.URL,
		BrainPub:  bpub,
		Recipe:    testRecipe(),
		SocksAddr: "127.0.0.1:0",
		Network:   func() string { return "mci" },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.Start(context.Background()); err == nil {
		eng.Stop()
		t.Fatal("engine started on an assignment with an invalid signature; it must reject it")
	}
}
