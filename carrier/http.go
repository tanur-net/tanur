// SPDX-License-Identifier: MPL-2.0

// Package carrier provides an HTTP carrier: a reliable bidirectional byte stream
// tunneled inside HTTP, so the whole stack (inner handshake, mux, tunnel) rides
// on top of it unchanged, exactly as it rides on the TLS skin.
//
// Why: a CDN (Gcore, Cloudflare, ...) terminates TLS and forwards only HTTP to
// origin, so behind a CDN we cannot run our raw channel over the TLS stream. We
// carry it inside HTTP bodies, which also gives the request/response
// (small-up, large-down) shape real browsing has. (docs/dpi-and-shaper S9)
//
// Model: SPLIT, because HTTP/1.1 and most CDNs do not allow a single full-duplex
// request (Go's HTTP/1.1 client will not read the response until the whole
// request body is written). So each direction is its own half-duplex request,
// paired by a session id:
//
//	downlink: GET  ?sid=X&dir=down   response body streams server -> client
//	uplink:   POST ?sid=X&dir=up     request  body streams client -> server
//
// This is the same reason XHTTP uses a split design.
package carrier

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"sync"
	"time"
)

// Server resource bounds. A carrier session is "half-open" until BOTH its up and
// down requests have arrived; without limits, an attacker (or a flaky CDN) that
// sends only one side for many distinct sids would pin unbounded sessions and
// handlers in memory — a cheap denial of service. These cap the exposure.
const (
	defaultMaxSessions     = 2048
	defaultHalfOpenTimeout = 30 * time.Second
)

// Conn is a bidirectional byte stream over HTTP (io.ReadWriteCloser).
type Conn struct {
	r      io.Reader
	w      io.Writer
	closer func() error
}

func (c *Conn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *Conn) Write(p []byte) (int, error) { return c.w.Write(p) }
func (c *Conn) Close() error                { return c.closer() }

// --- client side ---

// Dial opens the carrier: a down GET (server->client) and an up POST
// (client->server), correlated by a fresh session id. baseURL is the carrier
// endpoint (the path the CDN routes to the server handler).
func Dial(client *http.Client, baseURL string) (*Conn, error) {
	sid := newSID()

	// Downlink first, so the server has the write side before the client sends.
	downReq, err := http.NewRequest("GET", baseURL+"?sid="+sid+"&dir=down", nil)
	if err != nil {
		return nil, err
	}
	downReq.Header.Set("Cache-Control", "no-store")
	downResp, err := client.Do(downReq)
	if err != nil {
		return nil, err
	}
	if downResp.StatusCode != http.StatusOK {
		downResp.Body.Close()
		return nil, &statusError{downResp.StatusCode}
	}

	// Uplink: a streaming POST body we write into. Its response only arrives
	// when we close the body, so run Do in the background.
	pr, pw := io.Pipe()
	upReq, err := http.NewRequest("POST", baseURL+"?sid="+sid+"&dir=up", pr)
	if err != nil {
		downResp.Body.Close()
		return nil, err
	}
	upReq.Header.Set("Content-Type", "application/octet-stream")
	upReq.Header.Set("Cache-Control", "no-store")
	go func() {
		if resp, err := client.Do(upReq); err == nil {
			resp.Body.Close()
		}
	}()

	return &Conn{
		r: downResp.Body,
		w: pw,
		closer: func() error {
			pw.Close()
			downResp.Body.Close()
			return nil
		},
	}, nil
}

func newSID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// --- server side ---

// HTTPServer pairs the up and down requests of each session into one Conn and
// calls Handle with it once, exactly once per session. Mount ServeHTTP on the
// carrier path of an http.Server (which the CDN forwards to).
type HTTPServer struct {
	// Handle runs the stack (inner.Server + mux + exit) on each carrier Conn.
	Handle func(io.ReadWriteCloser)

	// MaxSessions caps concurrent (including half-open) sessions; 0 uses the
	// default. A new session beyond the cap is refused with 503.
	MaxSessions int
	// HalfOpenTimeout is how long a session may wait for its second half before
	// it is reaped; 0 uses the default.
	HalfOpenTimeout time.Duration

	mu   sync.Mutex
	sess map[string]*session
}

type session struct {
	up        io.ReadCloser // server reads client->server here
	down      io.Writer     // server writes server->client here
	done      chan struct{} // closed when the Conn is closed
	timer     *time.Timer   // half-open reaper; stopped once both halves arrive
	fireOnce  sync.Once
	closeOnce sync.Once
}

func (s *HTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sid := r.URL.Query().Get("sid")
	dir := r.URL.Query().Get("dir")
	if sid == "" || (dir != "up" && dir != "down") {
		http.Error(w, "bad carrier request", http.StatusBadRequest)
		return
	}
	sess, ok := s.getOrCreate(sid)
	if !ok {
		http.Error(w, "carrier busy", http.StatusServiceUnavailable)
		return
	}

	switch dir {
	case "down":
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()
		s.setDown(sid, sess, &flushWriter{w: w, f: flusher})
	case "up":
		s.setUp(sid, sess, r.Body)
	}

	// Block this HTTP handler until the Conn is closed, so the body stays open.
	// Also return if the client goes away, so a disconnect tears the session
	// down instead of leaking it (and unblocks a half-open peer).
	select {
	case <-sess.done:
	case <-r.Context().Done():
		s.teardown(sid, sess)
	}
}

// getOrCreate returns the session for sid, creating it if new. It returns ok ==
// false when a NEW session would exceed MaxSessions, so the handler can refuse
// rather than grow without bound. A newly created session gets a half-open timer.
func (s *HTTPServer) getOrCreate(sid string) (*session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sess == nil {
		s.sess = make(map[string]*session)
	}
	if se := s.sess[sid]; se != nil {
		return se, true
	}
	max := s.MaxSessions
	if max <= 0 {
		max = defaultMaxSessions
	}
	if len(s.sess) >= max {
		return nil, false
	}
	se := &session{done: make(chan struct{})}
	s.sess[sid] = se
	to := s.HalfOpenTimeout
	if to <= 0 {
		to = defaultHalfOpenTimeout
	}
	se.timer = time.AfterFunc(to, func() { s.teardown(sid, se) })
	return se, true
}

// teardown removes a session and unblocks its handlers. It is idempotent and
// safe whether the session fired or is still half-open: the half-open reaper,
// a client disconnect, and normal completion all route through it.
func (s *HTTPServer) teardown(sid string, se *session) {
	s.mu.Lock()
	if s.sess[sid] == se {
		delete(s.sess, sid)
	}
	if se.timer != nil {
		se.timer.Stop()
	}
	s.mu.Unlock()
	se.closeOnce.Do(func() { close(se.done) })
}

func (s *HTTPServer) setUp(sid string, se *session, up io.ReadCloser) {
	s.mu.Lock()
	se.up = up
	ready := se.up != nil && se.down != nil
	s.mu.Unlock()
	if ready {
		s.fire(sid, se)
	}
}

func (s *HTTPServer) setDown(sid string, se *session, down io.Writer) {
	s.mu.Lock()
	se.down = down
	ready := se.up != nil && se.down != nil
	s.mu.Unlock()
	if ready {
		s.fire(sid, se)
	}
}

// fire builds the Conn and calls Handle exactly once, then cleans up.
func (s *HTTPServer) fire(sid string, se *session) {
	se.fireOnce.Do(func() {
		// Cancel the half-open reaper so it can't tear down a now-live session.
		s.mu.Lock()
		if se.timer != nil {
			se.timer.Stop()
		}
		s.mu.Unlock()

		conn := &Conn{
			r: se.up,
			w: se.down,
			closer: func() error {
				se.closeOnce.Do(func() { close(se.done) })
				return nil
			},
		}
		go func() {
			if s.Handle != nil {
				s.Handle(conn)
			}
			conn.Close()
			s.teardown(sid, se)
		}()
	})
}

type flushWriter struct {
	w io.Writer
	f http.Flusher
}

func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if n > 0 {
		fw.f.Flush()
	}
	return n, err
}

type statusError struct{ code int }

func (e *statusError) Error() string {
	return "carrier: unexpected HTTP status " + http.StatusText(e.code)
}
