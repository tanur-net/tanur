// SPDX-License-Identifier: MPL-2.0

package brain

import (
	"errors"
	"fmt"
)

// PoolEndpoint is one reachable path in the full fleet, as the server knows it.
// It carries only public information (the server's PUBLIC key, a URL/host); no
// secret ever goes into an assignment sent to a client. This is the client-side
// view: the server-side Pool that holds and rotates these lives separately.
type PoolEndpoint struct {
	ID        string `json:"id"`
	Label     string `json:"label"`    // "gcore", "cloudflare", "skin", "direct"
	Kind      string `json:"kind"`     // "carrier" | "skin" | "direct"
	Priority  int    `json:"priority"` // lower is preferred
	URL       string `json:"url"`      // carrier URL or host:port
	SNI       string `json:"sni,omitempty"`
	ServerPub []byte `json:"server_pub"`
	Burned    bool   `json:"-"` // globally burned (dead on every operator); never serialized out
	// BurnedOn marks operators where this endpoint is dead while it may still be
	// fine elsewhere. Field intel (docs/measurements/2026-10-05-field-intel-patt)
	// shows an IP can be throttled/blocked on Irancell yet clean on MCI, so burn
	// must be per operator; a global Burn is reserved for an IP dead everywhere.
	BurnedOn map[string]bool `json:"-"`
}

// Valid reports whether an endpoint delivered in a (signed) assignment is
// well-formed enough to dial. A valid signature proves the brain sent it, not
// that its contents make sense — so the client still rejects a garbage or
// truncated endpoint before the ladder ever tries to use it.
func (e PoolEndpoint) Valid() error {
	if e.ID == "" {
		return errors.New("brain: endpoint missing id")
	}
	switch e.Kind {
	case "skin", "carrier", "direct":
	default:
		return fmt.Errorf("brain: endpoint %q has bad kind %q", e.ID, e.Kind)
	}
	if e.URL == "" {
		return fmt.Errorf("brain: endpoint %q missing url", e.ID)
	}
	if len(e.ServerPub) != 32 { // Noise static public key (Curve25519)
		return fmt.Errorf("brain: endpoint %q server_pub must be 32 bytes, got %d", e.ID, len(e.ServerPub))
	}
	return nil
}
