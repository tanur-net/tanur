// SPDX-License-Identifier: MPL-2.0

// Command tanur-tunnel-client connects to a tanur-tunnel-server over the inner
// secure channel and exposes a local SOCKS5 proxy. Point a browser or
// `curl --socks5-hostname` at it and the traffic exits at the server.
package main

import (
	"encoding/base64"
	"flag"
	"log"
	"net"
	"time"

	"github.com/tanur-net/tanur/inner"
	"github.com/tanur-net/tanur/recipe"
	"github.com/tanur-net/tanur/tunnel"
)

func main() {
	server := flag.String("server", "127.0.0.1:9500", "tunnel server host:port")
	pubB64 := flag.String("pub", "", "base64 server public key (required)")
	socks := flag.String("socks", "127.0.0.1:1080", "local SOCKS5 listen address")
	flag.Parse()

	if *pubB64 == "" {
		log.Fatal("tanur-tunnel-client: -pub is required")
	}
	pub, err := base64.StdEncoding.DecodeString(*pubB64)
	if err != nil {
		log.Fatal("bad -pub:", err)
	}

	raw, err := net.DialTimeout("tcp", *server, 15*time.Second)
	if err != nil {
		log.Fatal("dial:", err)
	}
	if tc, ok := raw.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	conn, err := inner.Client(raw, pub, devRecipe())
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
	log.Printf("SOCKS5 proxy on %s -> tunnel -> %s", ln.Addr(), *server)
	if err := tunnel.SocksServer(ln, m); err != nil {
		log.Fatal("socks:", err)
	}
}

func devRecipe() recipe.Recipe {
	return recipe.Recipe{
		ID: "tunnel-dev", Version: 1,
		Skin:    recipe.SkinParams{ServerName: "localhost", ALPN: []string{"http/1.1"}},
		Frame:   recipe.IntDist{Min: 512, Max: 8192},
		Burst:   recipe.IntDist{Min: 16, Max: 64},
		Gap:     recipe.IntDist{Min: 0, Max: 5},
		Pause:   recipe.IntDist{Min: 0, Max: 0},
		Pad:     recipe.IntDist{Min: 0, Max: 128},
		Session: recipe.SessionBounds{MaxSeconds: 3600, MaxBytes: 2 << 30},
	}
}
