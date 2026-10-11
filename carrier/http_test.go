// SPDX-License-Identifier: MPL-2.0

package carrier

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/tanur-net/tanur/inner"
	"github.com/tanur-net/tanur/recipe"
)

func (s *HTTPServer) sessionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sess)
}

// A session that only ever gets one of its two halves must be reaped, not pinned
// in memory forever — the DoS that unbounded half-open sessions would allow.
func TestHalfOpenSessionReaped(t *testing.T) {
	hs := &HTTPServer{HalfOpenTimeout: 40 * time.Millisecond}
	req := httptest.NewRequest("GET", "/?sid=solo&dir=down", nil)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { hs.ServeHTTP(rec, req); close(done) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("half-open session handler was never reaped")
	}
	if n := hs.sessionCount(); n != 0 {
		t.Fatalf("reaped session still in map: %d", n)
	}
}

// A new session beyond MaxSessions is refused with 503 rather than growing the
// map without bound.
func TestSessionCapRefuses(t *testing.T) {
	hs := &HTTPServer{MaxSessions: 1, HalfOpenTimeout: time.Second}
	// First (half-open) session takes the only slot; its handler blocks.
	go hs.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/?sid=a&dir=down", nil))
	deadline := time.Now().Add(time.Second)
	for hs.sessionCount() < 1 {
		if time.Now().After(deadline) {
			t.Fatal("first session never registered")
		}
		time.Sleep(time.Millisecond)
	}
	// Second, distinct session must be refused.
	rec := httptest.NewRecorder()
	hs.ServeHTTP(rec, httptest.NewRequest("GET", "/?sid=b&dir=down", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("over-cap session: want 503, got %d", rec.Code)
	}
}

func testRecipe() recipe.Recipe {
	return recipe.Recipe{
		ID: "carrier", Version: 1,
		Skin:    recipe.SkinParams{ServerName: "example.com", ALPN: []string{"http/1.1"}},
		Frame:   recipe.IntDist{Min: 256, Max: 4096},
		Burst:   recipe.IntDist{Min: 8, Max: 32},
		Gap:     recipe.IntDist{Min: 0, Max: 0},
		Pause:   recipe.IntDist{Min: 0, Max: 0},
		Pad:     recipe.IntDist{Min: 0, Max: 64},
		Session: recipe.SessionBounds{MaxSeconds: 600, MaxBytes: 50 << 20},
	}
}

// The carrier alone must move bytes both directions over the split HTTP model.
func TestCarrierByteStream(t *testing.T) {
	hs := &HTTPServer{Handle: func(rw io.ReadWriteCloser) {
		buf := make([]byte, 4096)
		for {
			n, err := rw.Read(buf)
			if n > 0 {
				rw.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}}
	srv := httptest.NewServer(hs)
	defer srv.Close()

	conn, err := Dial(srv.Client(), srv.URL+"/carrier")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	msg := []byte("bytes over an http carrier")
	go conn.Write(msg)
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("carrier echo mismatch: %q", got)
	}
}

// The full secure channel must run over the carrier: inner handshake + framed
// data, server echoes, over HTTP.
func TestInnerOverCarrier(t *testing.T) {
	static, err := inner.GenerateStatic()
	if err != nil {
		t.Fatal(err)
	}
	r := testRecipe()

	hs := &HTTPServer{Handle: func(rw io.ReadWriteCloser) {
		conn, err := inner.Server(rw, static, r)
		if err != nil {
			return
		}
		buf := make([]byte, 16*1024)
		for {
			n, rerr := conn.Read(buf)
			if n > 0 {
				conn.Write(buf[:n])
			}
			if rerr != nil {
				return
			}
		}
	}}
	srv := httptest.NewServer(hs)
	defer srv.Close()

	cc, err := Dial(srv.Client(), srv.URL+"/carrier")
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()

	var conn *inner.Conn
	done := make(chan error, 1)
	go func() {
		var e error
		conn, e = inner.Client(cc, static.Public, r)
		done <- e
	}()
	select {
	case e := <-done:
		if e != nil {
			t.Fatalf("inner client over carrier: %v", e)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("inner handshake over carrier timed out")
	}

	payload := bytes.Repeat([]byte("tanur-over-http "), 500) // multi-frame
	go conn.Write(payload)
	got := make([]byte, 0, len(payload))
	buf := make([]byte, 8192)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for len(got) < len(payload) {
			n, err := conn.Read(buf)
			got = append(got, buf[:n]...)
			if err != nil {
				return
			}
		}
	}()
	waitCh := make(chan struct{})
	go func() { wg.Wait(); close(waitCh) }()
	select {
	case <-waitCh:
	case <-time.After(15 * time.Second):
		t.Fatalf("echo over carrier timed out; got %d/%d", len(got), len(payload))
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("inner-over-carrier mismatch: got %d want %d", len(got), len(payload))
	}
}
