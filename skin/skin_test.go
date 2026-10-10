// SPDX-License-Identifier: MPL-2.0

package skin

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/tanur-net/tanur/inner"
	"github.com/tanur-net/tanur/recipe"
)

// selfSigned makes a throwaway cert for "localhost" so the loopback test has a
// real TLS handshake. Production uses a real cert for the real domain.
func selfSigned(t *testing.T) (tls.Certificate, *x509.CertPool) {
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

func testRecipe() recipe.Recipe {
	return recipe.Recipe{
		ID: "skin-test", Version: 1,
		Skin:    recipe.SkinParams{ServerName: "localhost", ALPN: []string{"http/1.1"}},
		Frame:   recipe.IntDist{Min: 100, Max: 1200},
		Burst:   recipe.IntDist{Min: 8, Max: 64},
		Gap:     recipe.IntDist{Min: 0, Max: 5},
		Pause:   recipe.IntDist{Min: 0, Max: 0},
		Pad:     recipe.IntDist{Min: 0, Max: 128},
		Session: recipe.SessionBounds{MaxSeconds: 600, MaxBytes: 10 << 20},
	}
}

const doorSecret = "test-door-secret"

// startServer runs a skin server on a localhost listener and echoes inner data.
func startServer(t *testing.T) (addr string, pub []byte, stop func()) {
	t.Helper()
	cert, _ := selfSigned(t)
	static, err := inner.GenerateStatic()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ServerConfig{
		TLS:        &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		Static:     static,
		Recipe:     testRecipe(),
		DoorSecret: doorSecret,
		Site: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, "<title>real site</title>")
		}),
		OnInner: func(c *inner.Conn) {
			buf := make([]byte, 4096)
			for {
				n, err := c.Read(buf)
				if n > 0 {
					c.Write(buf[:n])
				}
				if err != nil {
					return
				}
			}
		},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				tc := tls.Server(raw, cfg.TLS)
				if err := tc.Handshake(); err != nil {
					raw.Close()
					return
				}
				cfg.Serve(tc)
			}()
		}
	}()
	stop = func() {
		ln.Close()
		close(done)
	}
	return ln.Addr().String(), static.Public, stop
}

// A Tanur client presents the door and gets the inner echo channel.
func TestTanurClientGetsInnerChannel(t *testing.T) {
	addr, pub, stop := startServer(t)
	defer stop()

	cc := &ClientConfig{
		Addr:       addr,
		TLS:        &tls.Config{ServerName: "localhost", InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		ServerPub:  pub,
		Recipe:     testRecipe(),
		DoorSecret: doorSecret,
	}
	conn, err := cc.Dial()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	msg := bytes.Repeat([]byte("tanur over tls skin "), 300) // multi-frame
	go conn.Write(msg)

	got := make([]byte, 0, len(msg))
	buf := make([]byte, 4096)
	for len(got) < len(msg) {
		n, err := conn.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo mismatch: %d vs %d", len(got), len(msg))
	}
}

// A browser (no door) gets the real site, not the inner channel.
func TestBrowserGetsRealSite(t *testing.T) {
	addr, _, stop := startServer(t)
	defer stop()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{ServerName: "localhost", InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
	}
	resp, err := client.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("browser get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !bytes.Contains(body, []byte("real site")) {
		t.Fatalf("browser did not get the real site: %d %q", resp.StatusCode, body)
	}
}

// A prober that connects with a wrong door token also just gets the site.
func TestWrongDoorGetsSite(t *testing.T) {
	addr, pub, stop := startServer(t)
	defer stop()

	cc := &ClientConfig{
		Addr:       addr,
		TLS:        &tls.Config{ServerName: "localhost", InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		ServerPub:  pub,
		Recipe:     testRecipe(),
		DoorSecret: "wrong-secret",
	}
	// The handshake will fail because the server serves HTTP, not the inner
	// channel, so Dial must return an error rather than a working tunnel.
	conn, err := cc.Dial()
	if err == nil {
		conn.Close()
		t.Fatal("wrong door produced a working inner channel")
	}
}

// effectiveTLS must apply an ECHConfigList when present and leave the caller's
// config untouched (clone), and return the original config when ECH is unset.
func TestEffectiveTLSAppliesECH(t *testing.T) {
	base := &tls.Config{ServerName: "example.com", MinVersion: tls.VersionTLS13}

	// No ECH: same config returned, nothing added.
	plain := &ClientConfig{TLS: base}
	if got := plain.effectiveTLS(); got != base {
		t.Fatal("without ECH, effectiveTLS should return the caller's own config")
	}
	if len(base.EncryptedClientHelloConfigList) != 0 {
		t.Fatal("caller config must not gain an ECH list when none was set")
	}

	// With ECH: a clone carries the list; the caller's config stays clean.
	ech := []byte{0xAB, 0xCD, 0xEF}
	withECH := &ClientConfig{TLS: base, ECHConfigList: ech}
	got := withECH.effectiveTLS()
	if got == base {
		t.Fatal("with ECH, effectiveTLS must return a clone, not mutate the caller's config")
	}
	if !bytes.Equal(got.EncryptedClientHelloConfigList, ech) {
		t.Fatalf("ECH list not applied: got %x", got.EncryptedClientHelloConfigList)
	}
	if len(base.EncryptedClientHelloConfigList) != 0 {
		t.Fatal("caller config was mutated; clone expected")
	}
}
