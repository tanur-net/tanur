// SPDX-License-Identifier: MPL-2.0

package inner

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/tanur-net/tanur/recipe"
)

// muxRecipe: no pauses, generous bounds, so the test exercises many streams fast.
func muxRecipe() recipe.Recipe {
	return recipe.Recipe{
		ID: "mux", Version: 1,
		Skin:    recipe.SkinParams{ServerName: "example.com", ALPN: []string{"http/1.1"}},
		Frame:   recipe.IntDist{Min: 100, Max: 1200},
		Burst:   recipe.IntDist{Min: 8, Max: 64},
		Gap:     recipe.IntDist{Min: 0, Max: 5},
		Pause:   recipe.IntDist{Min: 0, Max: 0},
		Pad:     recipe.IntDist{Min: 0, Max: 64},
		Session: recipe.SessionBounds{MaxSeconds: 600, MaxBytes: 100 << 20},
	}
}

// bringUp completes a handshake over net.Pipe and returns a client and server
// Conn ready for multiplexing.
func bringUp(t *testing.T) (*Conn, *Conn) {
	t.Helper()
	static, err := GenerateStatic()
	if err != nil {
		t.Fatal(err)
	}
	cliRaw, srvRaw := net.Pipe()
	r := muxRecipe()
	var srv *Conn
	var srvErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); srv, srvErr = Server(srvRaw, static, r) }()
	cli, err := Client(cliRaw, static.Public, r)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	wg.Wait()
	if srvErr != nil {
		t.Fatalf("server: %v", srvErr)
	}
	return cli, srv
}

// Many concurrent streams over one connection must stay independent and intact.
func TestMuxConcurrentStreams(t *testing.T) {
	cli, srv := bringUp(t)
	cm, err := ClientMux(cli)
	if err != nil {
		t.Fatal(err)
	}
	sm, err := ServerMux(srv)
	if err != nil {
		t.Fatal(err)
	}
	defer cm.Close()
	defer sm.Close()

	const n = 20

	// Server: accept n streams and echo each one.
	var sWG sync.WaitGroup
	sWG.Add(1)
	go func() {
		defer sWG.Done()
		var inner sync.WaitGroup
		for i := 0; i < n; i++ {
			st, err := sm.Accept()
			if err != nil {
				return
			}
			inner.Add(1)
			go func(s io.ReadWriteCloser) {
				defer inner.Done()
				io.Copy(s, s) // echo until closed
				s.Close()
			}(st)
		}
		inner.Wait()
	}()

	// Client: open n streams, each sends a distinct payload and checks the echo.
	var cWG sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		cWG.Add(1)
		go func(id int) {
			defer cWG.Done()
			st, err := cm.Open()
			if err != nil {
				errs <- fmt.Errorf("open %d: %w", id, err)
				return
			}
			defer st.Close()
			// Distinct, multi-frame payload per stream.
			msg := bytes.Repeat([]byte(fmt.Sprintf("stream-%02d|", id)), 500)
			// Write in a goroutine so a large write cannot deadlock against the
			// echo read on a flow-controlled stream.
			go st.Write(msg)
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(st, got); err != nil {
				errs <- fmt.Errorf("read %d: %w", id, err)
				return
			}
			if !bytes.Equal(got, msg) {
				errs <- fmt.Errorf("stream %d mismatch: got %d bytes want %d", id, len(got), len(msg))
			}
		}(i)
	}
	cWG.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	sWG.Wait()
}

// Streams must not bleed into each other: data written on one is never seen on
// another. Covered implicitly above by distinct payloads, but assert the count.
func TestMuxStreamCountAndClose(t *testing.T) {
	cli, srv := bringUp(t)
	cm, _ := ClientMux(cli)
	sm, _ := ServerMux(srv)

	done := make(chan struct{})
	go func() {
		for i := 0; i < 3; i++ {
			s, err := sm.Accept()
			if err != nil {
				return
			}
			go func(s io.ReadWriteCloser) { io.Copy(io.Discard, s) }(s)
		}
		close(done)
	}()

	var streams []io.ReadWriteCloser
	for i := 0; i < 3; i++ {
		s, err := cm.Open()
		if err != nil {
			t.Fatal(err)
		}
		s.Write([]byte("hi"))
		streams = append(streams, s)
	}
	<-done
	if got := cm.NumStreams(); got != 3 {
		t.Fatalf("NumStreams = %d, want 3", got)
	}
	for _, s := range streams {
		s.Close()
	}
	cm.Close()
	sm.Close()
}
