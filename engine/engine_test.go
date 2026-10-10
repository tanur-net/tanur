// SPDX-License-Identifier: MPL-2.0

package engine

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tanur-net/tanur/brain"
	"github.com/tanur-net/tanur/carrier"
	"github.com/tanur-net/tanur/inner"
	"github.com/tanur-net/tanur/recipe"
	"github.com/tanur-net/tanur/skin"
	"github.com/tanur-net/tanur/tunnel"
)

func testRecipe() recipe.Recipe {
	return recipe.Recipe{
		ID: "engine", Version: 1,
		Skin:    recipe.SkinParams{ServerName: "example.com", ALPN: []string{"http/1.1"}},
		Frame:   recipe.IntDist{Min: 512, Max: 8192},
		Burst:   recipe.IntDist{Min: 8, Max: 32},
		Gap:     recipe.IntDist{Min: 0, Max: 0},
		Pause:   recipe.IntDist{Min: 0, Max: 0},
		Pad:     recipe.IntDist{Min: 0, Max: 64},
		Session: recipe.SessionBounds{MaxSeconds: 600, MaxBytes: 50 << 20},
	}
}

// carrierTunnelServer starts an httptest server that runs the full exit stack
// (carrier -> inner.Server -> mux -> tunnel exit) on /t, and returns URL + pub.
func carrierTunnelServer(t *testing.T) (url string, pub []byte, stop func()) {
	t.Helper()
	static, err := inner.GenerateStatic()
	if err != nil {
		t.Fatal(err)
	}
	r := testRecipe()
	cs := &carrier.HTTPServer{Handle: func(rw io.ReadWriteCloser) {
		conn, err := inner.Server(rw, static, r)
		if err != nil {
			return
		}
		m, err := inner.ServerMux(conn)
		if err != nil {
			return
		}
		tunnel.ServeExit(m, 10*time.Second, nil)
	}}
	mux := http.NewServeMux()
	mux.Handle("/t", cs)
	srv := httptest.NewServer(mux)
	return srv.URL + "/t", static.Public, srv.Close
}

func TestEngineEndToEndOverCarrier(t *testing.T) {
	// A real target the tunnel must reach.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "reached-through-engine")
	}))
	defer target.Close()
	targetHost := strings.TrimPrefix(target.URL, "http://")

	curl, pub, stop := carrierTunnelServer(t)
	defer stop()

	eng, err := New(Config{
		Endpoints: []brain.PoolEndpoint{
			{ID: "cdn-1", Label: "gcore", Kind: "carrier", Priority: 0, URL: curl, ServerPub: pub},
		},
		Recipe:    testRecipe(),
		SocksAddr: "127.0.0.1:0",
		Network:   func() string { return "mci" },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer eng.Stop()

	body := socksGet(t, eng.Addr(), targetHost, "/")
	if !strings.Contains(body, "reached-through-engine") {
		t.Fatalf("did not reach target through engine; got %q", body)
	}
}

// With a dead endpoint first and a working one second, the engine must fail over.
func TestEngineFailsOverToWorkingEndpoint(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok-after-failover")
	}))
	defer target.Close()
	targetHost := strings.TrimPrefix(target.URL, "http://")

	curl, pub, stop := carrierTunnelServer(t)
	defer stop()

	eng, err := New(Config{
		Endpoints: []brain.PoolEndpoint{
			// Priority 0 is dead (nothing listening on this port).
			{ID: "dead", Label: "direct", Kind: "direct", Priority: 0, URL: "127.0.0.1:1", ServerPub: pub},
			// Priority 1 is the working carrier.
			{ID: "cdn-1", Label: "gcore", Kind: "carrier", Priority: 1, URL: curl, ServerPub: pub},
		},
		Recipe:    testRecipe(),
		SocksAddr: "127.0.0.1:0",
		Network:   func() string { return "mci" },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer eng.Stop()

	body := socksGet(t, eng.Addr(), targetHost, "/")
	if !strings.Contains(body, "ok-after-failover") {
		t.Fatalf("failover did not reach target; got %q", body)
	}
}

// socksGet dials a SOCKS5 proxy, CONNECTs to target, sends an HTTP/1.0 GET.
func socksGet(t *testing.T, proxyAddr, targetHostPort, path string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	c.Write([]byte{0x05, 0x01, 0x00})
	io.ReadFull(c, make([]byte, 2))
	host, portStr, _ := net.SplitHostPort(targetHostPort)
	port, _ := strconv.Atoi(portStr)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	req = append(req, pb[:]...)
	c.Write(req)
	resp := make([]byte, 10)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatalf("socks connect reply: %v", err)
	}
	if resp[1] != 0x00 {
		t.Fatalf("socks connect failed status %d", resp[1])
	}
	fmt.Fprintf(c, "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n", path, host)
	var sb strings.Builder
	io.Copy(&sb, bufio.NewReader(c))
	return sb.String()
}

// directTunnelServer runs the exit stack over raw TCP on the given network
// ("tcp", "tcp4", "tcp6"), for the engine's "direct" endpoint kind.
func directTunnelServer(t *testing.T, network, addr string) (dialAddr string, pub []byte, stop func()) {
	t.Helper()
	static, err := inner.GenerateStatic()
	if err != nil {
		t.Fatal(err)
	}
	r := testRecipe()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Skipf("cannot listen on %s %s (no IPv6?): %v", network, addr, err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(raw net.Conn) {
				conn, err := inner.Server(raw, static, r)
				if err != nil {
					raw.Close()
					return
				}
				m, err := inner.ServerMux(conn)
				if err != nil {
					raw.Close()
					return
				}
				tunnel.ServeExit(m, 10*time.Second, nil)
			}(c)
		}
	}()
	return ln.Addr().String(), static.Public, func() { ln.Close() }
}

// The engine must dial an IPv6 endpoint (client->server hop over [::1]) and
// carry traffic through it, proving IPv6 endpoints are first-class — the field
// intel flags IPv6 as a current bypass of the initial-upload limit.
func TestEngineOverIPv6Direct(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "reached-over-ipv6")
	}))
	defer target.Close()
	targetHost := strings.TrimPrefix(target.URL, "http://")

	addr, pub, stop := directTunnelServer(t, "tcp6", "[::1]:0")
	defer stop()
	if !strings.HasPrefix(addr, "[") {
		t.Fatalf("expected a bracketed IPv6 address, got %q", addr)
	}

	eng, err := New(Config{
		Endpoints: []brain.PoolEndpoint{
			{ID: "v6-1", Label: "direct", Kind: "direct", Priority: 0, URL: addr, ServerPub: pub},
		},
		Recipe:    testRecipe(),
		SocksAddr: "127.0.0.1:0",
		Network:   func() string { return "mci" },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.Start(context.Background()); err != nil {
		t.Fatalf("start over IPv6: %v", err)
	}
	defer eng.Stop()

	body := socksGet(t, eng.Addr(), targetHost, "/")
	if !strings.Contains(body, "reached-over-ipv6") {
		t.Fatalf("did not reach target over IPv6; got %q", body)
	}
}

// skinSelfSigned makes a throwaway localhost cert plus a pool that trusts it.
func skinSelfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	pool := x509.NewCertPool()
	parsed, _ := x509.ParseCertificate(der)
	pool.AddCert(parsed)
	return cert, pool
}

// skinTunnelServer runs the full exit stack behind the TLS skin + door: a real
// browser gets a site, a Tanur client is upgraded to the inner mux + exit.
func skinTunnelServer(t *testing.T, door string) (addr string, pub []byte, pool *x509.CertPool, stop func()) {
	t.Helper()
	cert, p := skinSelfSigned(t)
	static, err := inner.GenerateStatic()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &skin.ServerConfig{
		TLS:        &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		Static:     static,
		Recipe:     testRecipe(),
		DoorSecret: door,
		Site: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "<title>real site</title>")
		}),
		OnInner: func(c *inner.Conn) {
			m, err := inner.ServerMux(c)
			if err != nil {
				return
			}
			tunnel.ServeExit(m, 10*time.Second, nil)
		},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func(raw net.Conn) {
				tc := tls.Server(raw, cfg.TLS)
				if err := tc.Handshake(); err != nil {
					raw.Close()
					return
				}
				cfg.Serve(tc)
			}(raw)
		}
	}()
	return ln.Addr().String(), static.Public, p, func() { ln.Close() }
}

// The engine must dial a "skin" endpoint — real TLS to a real domain, door
// upgrade, inner channel — and carry traffic through it. The door secret rides
// in the recipe, the public endpoint carries only address + SNI.
func TestEngineOverSkin(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "reached-through-skin")
	}))
	defer target.Close()
	targetHost := strings.TrimPrefix(target.URL, "http://")

	const door = "engine-skin-door"
	addr, pub, pool, stop := skinTunnelServer(t, door)
	defer stop()

	r := testRecipe()
	r.Skin.ServerName = "localhost"
	r.Skin.DoorSecret = door // secret travels in the recipe, not the endpoint

	eng, err := New(Config{
		Endpoints: []brain.PoolEndpoint{
			{ID: "skin-1", Label: "skin", Kind: "skin", Priority: 0, URL: addr, SNI: "localhost", ServerPub: pub},
		},
		Recipe:    r,
		SocksAddr: "127.0.0.1:0",
		Network:   func() string { return "mci" },
		SkinTLS:   &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.Start(context.Background()); err != nil {
		t.Fatalf("start over skin: %v", err)
	}
	defer eng.Stop()

	body := socksGet(t, eng.Addr(), targetHost, "/")
	if !strings.Contains(body, "reached-through-skin") {
		t.Fatalf("did not reach target through skin; got %q", body)
	}
}
