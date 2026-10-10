// SPDX-License-Identifier: MPL-2.0

// Command tanur-skin-server runs the full outer skin over TLS: a browser gets a
// cover page, a Tanur client that presents the door is upgraded to the inner
// echo channel. Test tool. Uses a self-signed cert for first bring-up; a real
// domain + real cert is the production path.
package main

import (
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/tanur-net/tanur/inner"
	"github.com/tanur-net/tanur/internal/testcert"
	"github.com/tanur-net/tanur/recipe"
	"github.com/tanur-net/tanur/skin"
)

func main() {
	addr := flag.String("addr", "0.0.0.0:443", "listen address")
	sni := flag.String("sni", "localhost", "certificate / SNI name")
	door := flag.String("door", "tanur-test-door", "shared door secret")
	keyB64 := flag.String("key", "", "base64 server static private key; empty = generate")
	certFile := flag.String("cert", "", "path to a real TLS cert (PEM, e.g. Let's Encrypt fullchain.pem); needs -tlskey")
	tlsKeyFile := flag.String("tlskey", "", "path to the TLS private key (PEM, e.g. Let's Encrypt privkey.pem) for -cert")
	keygen := flag.Bool("keygen", false, "generate a stable static keypair, print base64 private+public, and exit")
	flag.Parse()

	if *keygen {
		k, err := inner.GenerateStatic()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("private:", base64.StdEncoding.EncodeToString(k.Private))
		fmt.Println("public: ", base64.StdEncoding.EncodeToString(k.Public))
		return
	}

	static, err := loadOrGen(*keyB64)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprintln(os.Stderr, "server public key:", base64.StdEncoding.EncodeToString(static.Public))

	tlsCfg, err := buildTLS(*sni, *certFile, *tlsKeyFile)
	if err != nil {
		log.Fatal(err)
	}

	cfg := &skin.ServerConfig{
		TLS:        tlsCfg,
		Static:     static,
		Recipe:     devRecipe(*sni),
		DoorSecret: *door,
		Site: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			io.WriteString(w, "<!doctype html><title>Welcome</title><h1>It works</h1>\n")
		}),
		OnInner: func(c *inner.Conn) {
			buf := make([]byte, 32*1024)
			for {
				n, rerr := c.Read(buf)
				if n > 0 {
					if _, werr := c.Write(buf[:n]); werr != nil {
						return
					}
				}
				if rerr != nil {
					return
				}
			}
		},
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(ln.Addr().String())
	for {
		raw, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func(c net.Conn) {
			if tc, ok := c.(*net.TCPConn); ok {
				tc.SetNoDelay(true)
			}
			tconn := tls.Server(c, cfg.TLS)
			if err := tconn.Handshake(); err != nil {
				c.Close()
				return
			}
			cfg.Serve(tconn)
		}(raw)
	}
}

// buildTLS picks the certificate source. A real test uses a real cert from
// files (-cert/-tlskey) — e.g. a Let's Encrypt pair that certbot obtained and
// renews on the server (fullchain.pem + privkey.pem). With neither flag it falls
// back to a self-signed cert, which is only honest for first bring-up, never for
// a real censorship test (a self-signed cert on a domain we do not own is itself
// a signal).
func buildTLS(sni, certFile, tlsKeyFile string) (*tls.Config, error) {
	if certFile != "" || tlsKeyFile != "" {
		if certFile == "" || tlsKeyFile == "" {
			return nil, fmt.Errorf("both -cert and -tlskey are required together")
		}
		pair, err := tls.LoadX509KeyPair(certFile, tlsKeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading real cert: %w", err)
		}
		fmt.Fprintf(os.Stderr, "TLS: real cert from %s\n", certFile)
		return &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, nil
	}
	cert, err := testcert.SelfSigned(sni)
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(os.Stderr, "TLS: SELF-SIGNED (bring-up only; not for a real test)")
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}

func loadOrGen(b64 string) (inner.StaticKey, error) {
	if b64 == "" {
		return inner.GenerateStatic()
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return inner.StaticKey{}, err
	}
	return inner.StaticFromPrivate(raw)
}

func devRecipe(sni string) recipe.Recipe {
	return recipe.Recipe{
		ID: "skin-dev", Version: 1,
		Skin:    recipe.SkinParams{ServerName: sni, ALPN: []string{"http/1.1"}},
		Frame:   recipe.IntDist{Min: 512, Max: 8192},
		Burst:   recipe.IntDist{Min: 16, Max: 64},
		Gap:     recipe.IntDist{Min: 0, Max: 10},
		Pause:   recipe.IntDist{Min: 0, Max: 0},
		Pad:     recipe.IntDist{Min: 0, Max: 128},
		Session: recipe.SessionBounds{MaxSeconds: 600, MaxBytes: 200 << 20},
	}
}
