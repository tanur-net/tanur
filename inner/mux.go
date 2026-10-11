// SPDX-License-Identifier: MPL-2.0

package inner

import (
	"io"
	"os"
	"time"

	"github.com/hashicorp/yamux"
)

// Multiplexing lets one secure connection carry many logical streams at once.
// This matters for two reasons the research made concrete:
//
//  1. A real device opens many simultaneous flows (tabs, apps, API calls). One
//     tunnel connection carrying many interleaved streams looks like an ordinary
//     multiplexed HTTPS/2 session, not like a single long symmetric tunnel.
//  2. Measured: collapsing many flows into one multiplexed connection dropped
//     flow-based VPN detection from ~75% to ~12-17%
//     (docs/dpi-and-shaper-requirements.md, requirement S1).
//
// We do NOT hand-roll multiplexing (it is plumbing, not crypto): yamux is a
// well-tested generic stream multiplexer over a single reliable byte stream,
// which is exactly what an inner Conn provides. yamux's own frames ride inside
// our encrypted, shaped Conn, so they are invisible to an observer.

// Mux is a multiplexed session over one inner Conn.
type Mux struct {
	sess *yamux.Session
}

// muxConfig returns yamux settings for the covert channel. Logging is silenced
// and flow-control control frames ride inside the encrypted stream.
//
// Keepalive is ENABLED. Measured on a real Android device: with it off, an idle
// mux's underlying TLS connection is dropped by the network/NAT after minutes of
// no traffic, and — without keepalive to notice — yamux keeps handing out
// streams on the dead session, so the next request after an idle period silently
// fails (the engine never learns to redial). Keepalive both refreshes the NAT
// mapping so the idle connection survives and detects a genuinely dead one so a
// redial happens. The pings ride INSIDE the TLS tunnel, so to an observer they
// are indistinguishable from the keepalives real long-lived HTTPS connections
// send (HTTP/2 PING, WebSocket ping); they are not an outer-channel signature.
// (A recipe-driven, jittered interval is a future refinement over the fixed one.)
func muxConfig() *yamux.Config {
	c := yamux.DefaultConfig()
	c.EnableKeepAlive = true
	c.KeepAliveInterval = 30 * time.Second
	c.ConnectionWriteTimeout = 30 * time.Second
	// Silenced in production; set TANUR_MUX_DEBUG=1 to surface yamux's own
	// session diagnostics (keepalive failures, protocol errors, shutdown reasons)
	// on stderr when debugging a dead-channel problem on a device.
	if os.Getenv("TANUR_MUX_DEBUG") != "" {
		c.LogOutput = os.Stderr
	} else {
		c.LogOutput = io.Discard
	}
	return c
}

// ClientMux turns an established client Conn into a multiplexed session. The
// client opens streams; the server accepts them.
func ClientMux(conn *Conn) (*Mux, error) {
	s, err := yamux.Client(conn, muxConfig())
	if err != nil {
		return nil, err
	}
	return &Mux{sess: s}, nil
}

// ServerMux turns an established server Conn into a multiplexed session.
func ServerMux(conn *Conn) (*Mux, error) {
	s, err := yamux.Server(conn, muxConfig())
	if err != nil {
		return nil, err
	}
	return &Mux{sess: s}, nil
}

// Open starts a new logical stream (client side). The returned stream is a
// net.Conn; for our purposes callers use it as an io.ReadWriteCloser.
func (m *Mux) Open() (io.ReadWriteCloser, error) {
	return m.sess.Open()
}

// Accept waits for the next logical stream opened by the peer (server side).
func (m *Mux) Accept() (io.ReadWriteCloser, error) {
	return m.sess.Accept()
}

// NumStreams reports how many logical streams are currently open.
func (m *Mux) NumStreams() int { return m.sess.NumStreams() }

// Close tears down the whole multiplexed session and the underlying Conn.
func (m *Mux) Close() error { return m.sess.Close() }
