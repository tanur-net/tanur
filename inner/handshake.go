// SPDX-License-Identifier: MPL-2.0

// Package inner is Tanur's own secure channel: the layer that lives *under* the
// outer TLS skin. It authenticates the two ends, encrypts everything, and hands
// up a framed byte stream whose frame sizes and timing are driven by a recipe
// via the shaper.
//
// Crypto is not invented here. The handshake is the standard Noise_IK pattern
// (github.com/flynn/noise) with X25519 + ChaCha20-Poly1305 + SHA-256. "IK"
// means the initiator already knows the responder's static public key, which is
// exactly our situation: the client receives the server's public key inside a
// signed recipe. Authentication therefore comes for free from the handshake.
//
// Design: docs/inner-protocol-v0.md layers 4 and 5.
package inner

import (
	"crypto/rand"
	"errors"

	"github.com/flynn/noise"
	"golang.org/x/crypto/curve25519"
)

// cipherSuite is fixed on purpose and documented in the design doc's "what is
// constant and why" table: a single modern suite, hidden inside the TLS skin.
var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

// StaticKey is a long-term X25519 keypair. The server has one; its public half
// travels to clients inside a signed recipe.
type StaticKey struct {
	noise.DHKey
}

// GenerateStatic makes a new server static keypair.
func GenerateStatic() (StaticKey, error) {
	k, err := cipherSuite.GenerateKeypair(rand.Reader)
	if err != nil {
		return StaticKey{}, err
	}
	return StaticKey{k}, nil
}

// StaticFromPrivate reconstructs a static keypair from a 32-byte X25519 private
// key, so a server can keep a stable identity across restarts. The public half
// is derived from the private key.
func StaticFromPrivate(priv []byte) (StaticKey, error) {
	if len(priv) != 32 {
		return StaticKey{}, errBadPrivLen
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return StaticKey{}, err
	}
	cp := make([]byte, 32)
	copy(cp, priv)
	return StaticKey{noise.DHKey{Private: cp, Public: pub}}, nil
}

var errBadPrivLen = errors.New("inner: private key must be 32 bytes")

// Session is an established secure channel: two cipher states, one per
// direction, produced by a completed handshake.
type Session struct {
	send *noise.CipherState
	recv *noise.CipherState
}

// handshakePayload is small and fixed-shape on purpose; real application data
// never rides the handshake messages.
var handshakePrologue = []byte("tanur/inner/v0")

// DialHandshake runs the initiator (client) side of Noise_IK against a responder
// whose static public key is serverPub. It returns the three wire messages to
// send/receive via the provided transport callbacks.
//
// writeMsg sends one handshake message; readMsg returns the next one. Keeping
// transport out of this function lets the same handshake run over a loopback in
// tests and over the real framed skin in production.
func DialHandshake(serverPub []byte, writeMsg func([]byte) error, readMsg func() ([]byte, error)) (*Session, error) {
	// Noise_IK requires the initiator to transmit its own static key, so the
	// client needs a static keypair too. For v0 it is generated fresh per
	// session (a throwaway identity): the server does not yet pin client keys,
	// and client-to-server authorization is carried separately by the door
	// token. Pinning a persistent client key can come later without changing
	// this handshake.
	clientStatic, err := cipherSuite.GenerateKeypair(rand.Reader)
	if err != nil {
		return nil, err
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		Prologue:      handshakePrologue,
		StaticKeypair: clientStatic,
		PeerStatic:    serverPub,
	})
	if err != nil {
		return nil, err
	}

	// -> e, es, s, ss
	msg, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, err
	}
	if err := writeMsg(msg); err != nil {
		return nil, err
	}

	// <- e, ee, se
	in, err := readMsg()
	if err != nil {
		return nil, err
	}
	_, cs0, cs1, err := hs.ReadMessage(nil, in)
	if err != nil {
		return nil, err
	}
	// Initiator: cs0 encrypts initiator->responder, cs1 the other way.
	return &Session{send: cs0, recv: cs1}, nil
}

// AcceptHandshake runs the responder (server) side of Noise_IK using its static
// keypair. Transport is injected the same way as DialHandshake.
func AcceptHandshake(static StaticKey, readMsg func() ([]byte, error), writeMsg func([]byte) error) (*Session, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeIK,
		Initiator:     false,
		Prologue:      handshakePrologue,
		StaticKeypair: static.DHKey,
	})
	if err != nil {
		return nil, err
	}

	// -> e, es, s, ss
	in, err := readMsg()
	if err != nil {
		return nil, err
	}
	if _, _, _, err := hs.ReadMessage(nil, in); err != nil {
		return nil, err
	}

	// <- e, ee, se
	msg, cs0, cs1, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, err
	}
	if err := writeMsg(msg); err != nil {
		return nil, err
	}
	// Responder: cs0 encrypts initiator->responder (so that's our recv), cs1 is
	// responder->initiator (our send).
	return &Session{send: cs1, recv: cs0}, nil
}
