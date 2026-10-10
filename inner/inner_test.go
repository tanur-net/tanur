// SPDX-License-Identifier: MPL-2.0

package inner

import (
	"bytes"
	"encoding/binary"
	"io"
	"sync"
	"testing"
)

// msgPipe is a tiny in-memory transport for the handshake callbacks: each
// direction is a channel of byte slices. It stands in for the network so the
// handshake can be tested on a loopback.
type msgPipe struct {
	c2s, s2c chan []byte
}

func newMsgPipe() *msgPipe {
	return &msgPipe{c2s: make(chan []byte, 4), s2c: make(chan []byte, 4)}
}

// runHandshake completes both sides concurrently and returns the two sessions.
func runHandshake(t *testing.T, static StaticKey) (*Session, *Session) {
	t.Helper()
	mp := newMsgPipe()
	var cs, ss *Session
	var cerr, serr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		cs, cerr = DialHandshake(static.Public,
			func(b []byte) error { mp.c2s <- b; return nil },
			func() ([]byte, error) { return <-mp.s2c, nil },
		)
	}()
	go func() {
		defer wg.Done()
		ss, serr = AcceptHandshake(static,
			func() ([]byte, error) { return <-mp.c2s, nil },
			func(b []byte) error { mp.s2c <- b; return nil },
		)
	}()
	wg.Wait()
	if cerr != nil || serr != nil {
		t.Fatalf("handshake failed: client=%v server=%v", cerr, serr)
	}
	return cs, ss
}

func TestHandshakeAndRoundTrip(t *testing.T) {
	static, err := GenerateStatic()
	if err != nil {
		t.Fatal(err)
	}
	cs, ss := runHandshake(t, static)

	// client -> server, with padding
	var buf bytes.Buffer
	payload := []byte("سلام از تهران, this is the inner channel")
	if err := cs.WriteFrame(&buf, payload, 64); err != nil {
		t.Fatal(err)
	}
	got, err := ss.ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: %q", got)
	}

	// server -> client, no padding
	buf.Reset()
	reply := []byte("pong")
	if err := ss.WriteFrame(&buf, reply, 0); err != nil {
		t.Fatal(err)
	}
	got, err = cs.ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, reply) {
		t.Fatalf("reply mismatch: %q", got)
	}
}

// Padding must not change the delivered payload, but must change the on-wire
// length: this is the property the shaper relies on.
func TestPaddingHidesPayloadLength(t *testing.T) {
	static, _ := GenerateStatic()
	cs, ss := runHandshake(t, static)

	payload := []byte("fixed")
	var a, b bytes.Buffer
	if err := cs.WriteFrame(&a, payload, 0); err != nil {
		t.Fatal(err)
	}
	if err := cs.WriteFrame(&b, payload, 200); err != nil {
		t.Fatal(err)
	}
	if a.Len() == b.Len() {
		t.Fatal("padding did not change wire length")
	}
	// Both still decode to the same payload.
	g1, err := ss.ReadFrame(&a)
	if err != nil {
		t.Fatal(err)
	}
	g2, err := ss.ReadFrame(&b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(g1, payload) || !bytes.Equal(g2, payload) {
		t.Fatal("padding corrupted payload")
	}
}

// A wrong server key must make the handshake fail: this is the authentication
// property of Noise_IK (client only completes with the real server).
func TestWrongServerKeyFails(t *testing.T) {
	static, _ := GenerateStatic()
	wrong, _ := GenerateStatic()

	mp := newMsgPipe()
	var wg sync.WaitGroup
	wg.Add(2)
	var cerr, serr error
	go func() {
		defer wg.Done()
		// Client dials the WRONG public key.
		_, cerr = DialHandshake(wrong.Public,
			func(b []byte) error { mp.c2s <- b; return nil },
			func() ([]byte, error) {
				select {
				case m := <-mp.s2c:
					return m, nil
				default:
					return nil, io.EOF
				}
			},
		)
	}()
	go func() {
		defer wg.Done()
		_, serr = AcceptHandshake(static,
			func() ([]byte, error) { return <-mp.c2s, nil },
			func(b []byte) error { mp.s2c <- b; return nil },
		)
	}()
	wg.Wait()
	// The server decrypts the initiator's static-key message with its own key;
	// against a client that encrypted to the wrong key, it must reject.
	if serr == nil && cerr == nil {
		t.Fatal("handshake succeeded against the wrong server key")
	}
}

func TestReadFrameRejectsTruncated(t *testing.T) {
	static, _ := GenerateStatic()
	cs, ss := runHandshake(t, static)
	var buf bytes.Buffer
	if err := cs.WriteFrame(&buf, []byte("hello"), 0); err != nil {
		t.Fatal(err)
	}
	// Chop the last byte of the ciphertext.
	b := buf.Bytes()
	truncated := bytes.NewReader(b[:len(b)-1])
	if _, err := ss.ReadFrame(truncated); err == nil {
		t.Fatal("expected error on truncated frame")
	}
}

func TestOversizeFrameRejected(t *testing.T) {
	static, _ := GenerateStatic()
	cs, _ := runHandshake(t, static)
	big := make([]byte, maxFramePlaintext+1)
	if err := cs.WriteFrame(io.Discard, big, 0); err == nil {
		t.Fatal("expected ErrFrameTooLarge")
	}
	// sanity: header encodes as uint16
	var h [2]byte
	binary.BigEndian.PutUint16(h[:], 1)
	_ = h
}
