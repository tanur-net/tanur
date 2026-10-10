// SPDX-License-Identifier: MPL-2.0

package brain

// PoolEndpoint is one reachable path in the full fleet, as the server knows it.
// It carries only public information (the server's PUBLIC key, a URL/host); no
// secret ever goes into an assignment sent to a client.
//
// This is the on-wire shape a client receives inside a signed Assignment, so it
// is part of the client-side (open) surface. The server-side set that holds and
// rotates these endpoints (the pool, the per-user subset, the steering) is not
// part of the open release. (CLAUDE.md rule 8 / S7)
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
