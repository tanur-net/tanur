// SPDX-License-Identifier: MPL-2.0

// Command tanur-ctun-client is the production-shaped client: it dials the HTTP
// carrier (a CDN URL in production), runs the secure channel + mux over it, and
// exposes a local SOCKS5 proxy. Apps pointed at the proxy exit at the server,
// with the origin hidden behind the CDN.
package main

import (
	"encoding/base64"
	"flag"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/tanur-net/tanur/carrier"
	"github.com/tanur-net/tanur/inner"
	"github.com/tanur-net/tanur/recipe"
	"github.com/tanur-net/tanur/tunnel"
)

func main() {
	url := flag.String("url", "http://127.0.0.1:8080/4dc37c94", "carrier URL (CDN endpoint in production)")
	pubB64 := flag.String("pub", "", "base64 server public key (required)")
	socks := flag.String("socks", "127.0.0.1:1080", "local SOCKS5 listen address")
	flag.Parse()

	if *pubB64 == "" {
		log.Fatal("tanur-ctun-client: -pub is required")
	}
	pub, err := base64.StdEncoding.DecodeString(*pubB64)
	if err != nil {
		log.Fatal("bad -pub:", err)
	}

	httpClient := &http.Client{
		// No overall timeout: the carrier requests are long-lived streams.
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  true,
			TLSHandshakeTimeout: 15 * time.Second,
		},
	}

	cc, err := carrier.Dial(httpClient, *url)
	if err != nil {
		log.Fatal("carrier dial:", err)
	}
	conn, err := inner.Client(cc, pub, devRecipe())
	if err != nil {
		log.Fatal("handshake:", err)
	}
	m, err := inner.ClientMux(conn)
	if err != nil {
		log.Fatal("mux:", err)
	}

	ln, err := net.Listen("tcp", *socks)
	if err != nil {
		log.Fatal("socks listen:", err)
	}
	log.Printf("SOCKS5 on %s -> carrier %s", ln.Addr(), *url)
	log.Fatal(tunnel.SocksServer(ln, m))
}

func devRecipe() recipe.Recipe {
	return recipe.Recipe{
		ID: "ctun-dev", Version: 1,
		Skin:    recipe.SkinParams{ServerName: "localhost", ALPN: []string{"http/1.1"}},
		Frame:   recipe.IntDist{Min: 512, Max: 8192},
		Burst:   recipe.IntDist{Min: 16, Max: 64},
		Gap:     recipe.IntDist{Min: 0, Max: 5},
		Pause:   recipe.IntDist{Min: 0, Max: 0},
		Pad:     recipe.IntDist{Min: 0, Max: 128},
		Session: recipe.SessionBounds{MaxSeconds: 3600, MaxBytes: 2 << 30},
	}
}
