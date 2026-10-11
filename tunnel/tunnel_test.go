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

// The meter counts the application bytes the SOCKS proxy carries, in both
// directions, so the host app can show real traffic rather than zero.
func TestMeterCountsTraffic(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("x", 5000))
	}))
	defer target.Close()
	targetHost := strings.TrimPrefix(target.URL, "http://")

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
	sm, err := inner.ServerMux(srvConn)
	if err != nil {
		t.Fatal(err)
	}
	go ServeExit(sm, 10*time.Second, nil)
	cm, err := inner.ClientMux(cliConn)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	meter := &Meter{}
	go SocksServerMetered(ln, cm, "", "", meter)

	body := socksGet(t, ln.Addr().String(), targetHost, "/")
	if !strings.Contains(body, strings.Repeat("x", 5000)) {
		t.Fatal("did not get the full body through the tunnel")
	}
	if meter.Up() <= 0 {
		t.Fatalf("meter counted no upload, want > 0")
	}
	if meter.Down() < 5000 {
		t.Fatalf("meter download %d, want >= 5000 (the body)", meter.Down())
	}
}

// End to end over UDP: a real UDP echo server reached through the local SOCKS
// proxy via UDP ASSOCIATE, over the inner mux channel, out the exit's connected
// UDP socket. This is the path that carries DNS for a TUN-based VPN.
func TestUDPAssociateThroughTunnel(t *testing.T) {
	// 1. A UDP echo server as the destination.
	uaddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	echo, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			n, from, err := echo.ReadFromUDP(b)
			if err != nil {
				return
			}
			echo.WriteToUDP(append([]byte("echo:"), b[:n]...), from)
		}
	}()
	echoPort := echo.LocalAddr().(*net.UDPAddr).Port

	// 2. inner channel + mux + exit + SOCKS, as in the TCP test.
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
	sm, err := inner.ServerMux(srvConn)
	if err != nil {
		t.Fatal(err)
	}
	go ServeExit(sm, 10*time.Second, nil)
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

	// 3. SOCKS5 UDP ASSOCIATE.
	ctrl, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()
	ctrl.SetDeadline(time.Now().Add(10 * time.Second))
	ctrl.Write([]byte{0x05, 0x01, 0x00})
	io.ReadFull(ctrl, make([]byte, 2))
	// UDP ASSOCIATE with a 0.0.0.0:0 placeholder address.
	ctrl.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	rep := make([]byte, 10) // VER REP RSV ATYP(1) IPv4(4) PORT(2)
	if _, err := io.ReadFull(ctrl, rep); err != nil {
		t.Fatalf("no associate reply: %v", err)
	}
	if rep[1] != 0x00 {
		t.Fatalf("associate failed, status %d", rep[1])
	}
	relayIP := net.IPv4(rep[4], rep[5], rep[6], rep[7])
	relayPort := int(binary.BigEndian.Uint16(rep[8:10]))

	// 4. Send a datagram to the relay, wrapped for the echo destination.
	uc, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: relayIP, Port: relayPort})
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	payload := []byte("ping")
	dgram := []byte{0, 0, 0, 0x01, 127, 0, 0, 1}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(echoPort))
	dgram = append(dgram, pb[:]...)
	dgram = append(dgram, payload...)
	uc.Write(dgram)

	// 5. Read the echoed datagram back and strip the SOCKS UDP header.
	uc.SetReadDeadline(time.Now().Add(10 * time.Second))
	resp := make([]byte, 2048)
	n, err := uc.Read(resp)
	if err != nil {
		t.Fatalf("no udp reply through tunnel: %v", err)
	}
	// header: RSV RSV FRAG ATYP(1) IPv4(4) PORT(2) = 10 bytes for IPv4
	if n < 10 {
		t.Fatalf("short udp reply: %d bytes", n)
	}
	got := string(resp[10:n])
	if got != "echo:ping" {
		t.Fatalf("want echo:ping through the UDP tunnel, got %q", got)
	}
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

// drainingOpener returns a stream whose far end is drained, so a CONNECT that
// reaches writeTarget always succeeds. Enough to exercise the handshake.
func drainingOpener() StreamOpener {
	return openFunc(func() (io.ReadWriteCloser, error) {
		a, b := net.Pipe()
		go io.Copy(io.Discard, b)
		return a, nil
	})
}

// TestSocksAuth covers the RFC 1929 login that Android's hev-socks5-tunnel
// speaks: the right username/password connects, the wrong one is rejected at
// the auth step, and a client that offers only no-auth is turned away — so the
// loopback port cannot be borrowed by another app without the session secret.
func TestSocksAuth(t *testing.T) {
	const user, pass = "sess-user", "sess-pass"
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go SocksServerAuth(ln, drainingOpener(), user, pass)

	// 1. Correct credentials: method 0x02 selected, login ok, CONNECT ok.
	t.Run("correct", func(t *testing.T) {
		c, _ := net.Dial("tcp", ln.Addr().String())
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		// greeting: offer no-auth AND user/pass, as hev does.
		c.Write([]byte{0x05, 0x02, 0x00, 0x02})
		rep := make([]byte, 2)
		io.ReadFull(c, rep)
		if rep[1] != 0x02 {
			t.Fatalf("want method 0x02, got 0x%02x", rep[1])
		}
		// RFC 1929: VER ULEN uname PLEN passwd
		login := []byte{0x01, byte(len(user))}
		login = append(login, user...)
		login = append(login, byte(len(pass)))
		login = append(login, pass...)
		c.Write(login)
		ar := make([]byte, 2)
		io.ReadFull(c, ar)
		if ar[0] != 0x01 || ar[1] != 0x00 {
			t.Fatalf("want auth success 01 00, got %v", ar)
		}
		// CONNECT to a domain target.
		c.Write([]byte{0x05, 0x01, 0x00, 0x03, byte(len("example.com"))})
		c.Write([]byte("example.com"))
		c.Write([]byte{0x00, 0x50})
		resp := make([]byte, 10)
		io.ReadFull(c, resp)
		if resp[1] != 0x00 {
			t.Fatalf("want connect success, got status %d", resp[1])
		}
	})

	// 2. Wrong password: rejected at the auth step (01 01), no CONNECT.
	t.Run("wrong-password", func(t *testing.T) {
		c, _ := net.Dial("tcp", ln.Addr().String())
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		c.Write([]byte{0x05, 0x01, 0x02})
		io.ReadFull(c, make([]byte, 2))
		login := []byte{0x01, byte(len(user))}
		login = append(login, user...)
		login = append(login, byte(len("nope")))
		login = append(login, "nope"...)
		c.Write(login)
		ar := make([]byte, 2)
		if _, err := io.ReadFull(c, ar); err != nil {
			t.Fatalf("expected an auth reply: %v", err)
		}
		if ar[0] != 0x01 || ar[1] == 0x00 {
			t.Fatalf("want auth failure, got %v", ar)
		}
	})

	// 3. Offers only no-auth: no acceptable method (0xFF).
	t.Run("no-auth-only", func(t *testing.T) {
		c, _ := net.Dial("tcp", ln.Addr().String())
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		c.Write([]byte{0x05, 0x01, 0x00})
		rep := make([]byte, 2)
		if _, err := io.ReadFull(c, rep); err != nil {
			t.Fatalf("expected a method reply: %v", err)
		}
		if rep[1] != 0xFF {
			t.Fatalf("want no-acceptable-method 0xFF, got 0x%02x", rep[1])
		}
	})
}
