// SPDX-License-Identifier: MPL-2.0

package inner

import (
	"io"
	"time"

	"github.com/tanur-net/tanur/internal/shaper"
	"github.com/tanur-net/tanur/recipe"
)

// Conn is a secure, shaped byte stream: it ties a completed Noise Session to a
// shaper so that application writes are split into frames whose sizes, padding
// and pauses come from the recipe. It satisfies io.ReadWriteCloser over any
// underlying stream (a TCP socket in production, a pipe in tests).
//
// The shaper is used on the write path only; the read path simply reassembles
// whatever frames arrive. Only the sender shapes its own direction, which is
// what an observer on that side sees.
type Conn struct {
	rw     io.ReadWriteCloser
	sess   *Session
	shaper *shaper.Shaper
	// sleep lets tests disable real pauses; production uses time.Sleep.
	sleep func(time.Duration)

	readBuf []byte // leftover decrypted payload not yet returned by Read
}

// NewConn wraps an underlying stream whose handshake has already completed,
// producing a shaped secure connection. nonce seeds the shaper.
func NewConn(rw io.ReadWriteCloser, sess *Session, r recipe.Recipe, nonce []byte) (*Conn, error) {
	sh, err := shaper.New(r, nonce)
	if err != nil {
		return nil, err
	}
	return &Conn{rw: rw, sess: sess, shaper: sh, sleep: time.Sleep}, nil
}

// Write shapes p into one or more frames and sends them. It returns len(p) on
// success. If the session's bounds are reached mid-write it returns the bytes
// sent so far together with shaper.ErrSessionExhausted, and the caller should
// redial.
func (c *Conn) Write(p []byte) (int, error) {
	sent := 0
	for sent < len(p) {
		step, err := c.shaper.Next(len(p) - sent)
		if err != nil {
			return sent, err
		}
		if step.PauseMS > 0 {
			c.sleep(time.Duration(step.PauseMS) * time.Millisecond)
		}
		end := sent + step.Payload
		if end > len(p) {
			end = len(p)
		}
		if err := c.sess.WriteFrame(c.rw, p[sent:end], step.Pad); err != nil {
			return sent, err
		}
		if step.Payload == 0 {
			// A zero-payload (idle) frame carries no application bytes; avoid an
			// infinite loop when there is still data to send.
			continue
		}
		sent = end
	}
	return sent, nil
}

// Read returns decrypted application bytes, reassembling across frames. Padding
// is already stripped by the frame layer.
func (c *Conn) Read(p []byte) (int, error) {
	if len(c.readBuf) == 0 {
		payload, err := c.sess.ReadFrame(c.rw)
		if err != nil {
			return 0, err
		}
		c.readBuf = payload
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

// Close closes the underlying stream.
func (c *Conn) Close() error { return c.rw.Close() }
