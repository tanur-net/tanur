// SPDX-License-Identifier: MPL-2.0

package inner

import (
	"crypto/rand"
	"encoding/binary"
	"io"

	"github.com/tanur-net/tanur/recipe"
)

// This file runs the handshake over a raw byte stream (a socket) by
// length-prefixing each handshake message, then returns a shaped Conn. The
// handshake-over-callbacks form in handshake.go stays transport-agnostic; this
// is the stream adapter.

func writeLenPrefixed(w io.Writer, msg []byte) error {
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(msg)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(msg)
	return err
}

func readLenPrefixed(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	msg := make([]byte, binary.BigEndian.Uint16(hdr[:]))
	if _, err := io.ReadFull(r, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

// Client completes the initiator handshake over rw against a server whose
// public key is serverPub, then returns a shaped secure Conn. The shaper nonce
// is random per session; it need not match the server's.
func Client(rw io.ReadWriteCloser, serverPub []byte, r recipe.Recipe) (*Conn, error) {
	sess, err := DialHandshake(serverPub,
		func(b []byte) error { return writeLenPrefixed(rw, b) },
		func() ([]byte, error) { return readLenPrefixed(rw) },
	)
	if err != nil {
		return nil, err
	}
	nonce, err := randomNonce()
	if err != nil {
		return nil, err
	}
	return NewConn(rw, sess, r, nonce)
}

// Server completes the responder handshake over rw using its static key, then
// returns a shaped secure Conn.
func Server(rw io.ReadWriteCloser, static StaticKey, r recipe.Recipe) (*Conn, error) {
	sess, err := AcceptHandshake(static,
		func() ([]byte, error) { return readLenPrefixed(rw) },
		func(b []byte) error { return writeLenPrefixed(rw, b) },
	)
	if err != nil {
		return nil, err
	}
	nonce, err := randomNonce()
	if err != nil {
		return nil, err
	}
	return NewConn(rw, sess, r, nonce)
}

func randomNonce() ([]byte, error) {
	b := make([]byte, recipe.NonceLen)
	_, err := rand.Read(b)
	return b, err
}
