// SPDX-License-Identifier: MPL-2.0

package tunnel

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tanur-net/tanur/inner"
	"github.com/tanur-net/tanur/recipe"
)

func testRecipe() recipe.Recipe {
	return recipe.Recipe{
		ID: "tunnel", Version: 1,
		Skin:    recipe.SkinParams{ServerName: "example.com", ALPN: []string{"http/1.1"}},
		Frame:   recipe.IntDist{Min: 256, Max: 4096},
		Burst:   recipe.IntDist{Min: 8, Max: 32},
		Gap:     recipe.IntDist{Min: 0, Max: 0},
		Pause:   recipe.IntDist{Min: 0, Max: 0},
		Pad:     recipe.IntDist{Min: 0, Max: 64},
		Session: recipe.SessionBounds{MaxSeconds: 600, MaxBytes: 50 << 20},
	}
}

// End to end: a real HTTP server, reached through the local SOCKS proxy, over
// the inner mux channel, out the server exit. This exercises the whole data
// path that makes Tanur a forwarding tunnel rather than an echo.
func TestSocksThroughTunnelToRealServer(t *testing.T) {
	// 1. A real target the tunnel must reach.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello-through-tanur")
	}))
	defer target.Close()
	targetHost := strings.TrimPrefix(target.URL, "http://") // 127.0.0.1:PORT

	// 2. inner secure channel over an in-memory socket pair.
	static, err := inner.GenerateStatic()
	if err != nil {
		t.Fatal(err)
	}
	cliRaw, srvRaw := net.Pipe()
	r := testRecipe()
	var srvConn *inner.Conn
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); srvConn, _ = inner.Server(srvRaw, static, r) }()
	cliConn, err := inner.Client(cliRaw, static.Public, r)
	if err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if srvConn == nil {
		t.Fatal("server handshake failed")
	}

	// 3. Server side: mux + exit.
	sm, err := inner.ServerMux(srvConn)
	if err != nil {
		t.Fatal(err)
	}
	go ServeExit(sm, 10*time.Second, nil)

	// 4. Client side: mux + local SOCKS proxy.
	cm, err := inner.ClientMux(cliConn)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go SocksServer(ln, cm)

	// 5. A SOCKS5 client: connect to the local proxy, CONNECT to the target,
	// then speak HTTP through the tunnel.
	body := socksGet(t, ln.Addr().String(), targetHost, "/")
	if !strings.Contains(body, "hello-through-tanur") {
		t.Fatalf("did not get target response through the tunnel; got %q", body)
	}
}

// socksGet dials proxyAddr with SOCKS5, CONNECTs to targetHostPort, sends a
// minimal HTTP/1.0 GET, and returns the response text.
func socksGet(t *testing.T, proxyAddr, targetHostPort, path string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))

	// greeting: ver5, 1 method, no-auth
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 2)
	if _, err := io.ReadFull(c, rep); err != nil {
		t.Fatal(err)
	}
	if rep[0] != 0x05 || rep[1] != 0x00 {
		t.Fatalf("socks greeting rejected: %v", rep)
	}

	host, portStr, _ := net.SplitHostPort(targetHostPort)
	port, _ := strconv.Atoi(portStr)
	// request: ver5, connect, rsv, atyp=domain, len, host, port
	buf := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	buf = append(buf, []byte(host)...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	buf = append(buf, pb[:]...)
	if _, err := c.Write(buf); err != nil {
		t.Fatal(err)
	}
	connResp := make([]byte, 10)
	if _, err := io.ReadFull(c, connResp); err != nil {
		t.Fatal(err)
	}
	if connResp[1] != 0x00 {
		t.Fatalf("socks connect failed, status %d", connResp[1])
	}

	// Now the tunnel is open to the target; speak HTTP.
	fmt.Fprintf(c, "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n", path, host)
	br := bufio.NewReader(c)
	var sb strings.Builder
	io.Copy(&sb, br)
	return sb.String()
}

// Unsupported SOCKS command must be rejected cleanly.
func TestSocksRejectsNonConnect(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	// open is never used because the command is rejected before opening a stream.
	go SocksServer(ln, openFunc(func() (io.ReadWriteCloser, error) {
		t.Error("stream opened for an unsupported command")
		return nil, fmt.Errorf("should not open")
	}))

	c, _ := net.Dial("tcp", ln.Addr().String())
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte{0x05, 0x01, 0x00})
	io.ReadFull(c, make([]byte, 2))
	// BIND command (0x02), not CONNECT
	c.Write([]byte{0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4, 0, 80})
	resp := make([]byte, 10)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatalf("expected a reply: %v", err)
	}
	if resp[1] != 0x07 {
		t.Fatalf("expected command-not-supported (0x07), got %d", resp[1])
	}
}

type openFunc func() (io.ReadWriteCloser, error)

func (f openFunc) Open() (io.ReadWriteCloser, error) { return f() }
