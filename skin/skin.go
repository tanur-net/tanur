// SPDX-License-Identifier: MPL-2.0

// Package skin is the outer, visible layer of a Tanur connection: a real TLS 1.3
// connection to a real domain we own, carrying an ordinary-looking HTTP request.
// Underneath that, once both ends agree, the inner secure channel runs.
//
// The design goal is that to anyone watching, the connection is one of millions
// of HTTPS sessions: a genuine TLS handshake to a genuine site with a genuine
// certificate. A browser that connects gets a real web page. A Tanur client
// presents a door token and is upgraded to the inner channel.
//
// This file holds the shared door logic; server.go and client.go hold the two
// ends. Design: docs/inner-protocol-v0.md layers 1 and 2.
package skin

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// The "door" is how the server tells a Tanur client apart from a real browser
// without any fixed, greppable constant on the wire. The client proves it knows
// a shared door secret by sending an HMAC over a fresh random value; the server
// recomputes it. A browser never sends this, so it just gets the website.
//
// The door secret is per-deployment and travels in the signed recipe; it is not
// a credential for the tunnel itself (that is the Noise handshake), only a
// quiet, unforgeable "this one is for me" signal that resists active probing: a
// prober that does not know the secret cannot produce a valid token and is
// handed the real site.

// doorToken computes the token a client sends, given the shared secret and a
// fresh client-chosen nonce (hex). Both sides compute it the same way.
func doorToken(secret, nonceHex string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(nonceHex))
	return hex.EncodeToString(mac.Sum(nil))
}

// verifyDoor checks a presented token against the expected one in constant time.
func verifyDoor(secret, nonceHex, presented string) bool {
	want := doorToken(secret, nonceHex)
	return hmac.Equal([]byte(want), []byte(presented))
}
