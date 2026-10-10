// SPDX-License-Identifier: MPL-2.0

package inner

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/tanur-net/tanur/recipe"
)

func itRecipe() recipe.Recipe {
	return recipe.Recipe{
		ID:      "it",
		Version: 1,
		Skin:    recipe.SkinParams{ServerName: "example.com", ALPN: []string{"http/1.1"}},
		Frame:   recipe.IntDist{Min: 100, Max: 1200},
		Burst:   recipe.IntDist{Min: 8, Max: 64},
		Gap:     recipe.IntDist{Min: 0, Max: 5},
		Pause:   recipe.IntDist{Min: 0, Max: 0}, // no pauses in tests
		Pad:     recipe.IntDist{Min: 0, Max: 128},
		Session: recipe.SessionBounds{MaxSeconds: 600, MaxBytes: 10 << 20},
	}
}

// End-to-end over an in-memory socket pair: handshake, then the client sends a
// multi-frame message and the server reads it back whole.
func TestEndToEndOverPipe(t *testing.T) {
	static, err := GenerateStatic()
	if err != nil {
		t.Fatal(err)
	}
	cliRaw, srvRaw := net.Pipe()
	r := itRecipe()

	var srvConn *Conn
	var srvErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		srvConn, srvErr = Server(srvRaw, static, r)
	}()

	cliConn, err := Client(cliRaw, static.Public, r)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	wg.Wait()
	if srvErr != nil {
		t.Fatalf("server: %v", srvErr)
	}

	// A payload larger than one frame, so the shaper must split it.
	msg := bytes.Repeat([]byte("the quick brown fox 0123456789 "), 400) // ~12 KB
	readDone := make(chan []byte, 1)
	go func() {
		got := make([]byte, 0, len(msg))
		buf := make([]byte, 4096)
		for len(got) < len(msg) {
			n, err := srvConn.Read(buf)
			if n > 0 {
				got = append(got, buf[:n]...)
			}
			if err != nil {
				if err == io.EOF {
					break
				}
				t.Errorf("server read: %v", err)
				break
			}
		}
		readDone <- got
	}()

	if _, err := cliConn.Write(msg); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got := <-readDone
	if !bytes.Equal(got, msg) {
		t.Fatalf("round trip mismatch: got %d bytes, want %d", len(got), len(msg))
	}
}

// Writing past the session byte bound must surface ErrSessionExhausted so the
// caller knows to redial, rather than silently overrunning.
func TestWriteStopsAtSessionBound(t *testing.T) {
	static, _ := GenerateStatic()
	cliRaw, srvRaw := net.Pipe()
	r := itRecipe()
	r.Session.MaxBytes = 4096

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Drain the server side so the client's writes do not block on the pipe.
		srv, err := Server(srvRaw, static, r)
		if err != nil {
			return
		}
		buf := make([]byte, 4096)
		for {
			if _, err := srv.Read(buf); err != nil {
				return
			}
		}
	}()

	cli, err := Client(cliRaw, static.Public, r)
	if err != nil {
		t.Fatal(err)
	}
	// Try to send far more than the bound.
	_, err = cli.Write(bytes.Repeat([]byte("x"), 1<<16))
	if err == nil {
		t.Fatal("expected session-bound error, got nil")
	}
	cli.Close()
	wg.Wait()
}
