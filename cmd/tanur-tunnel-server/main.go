// SPDX-License-Identifier: MPL-2.0

// Command tanur-tunnel-server is the exit end of the tunnel: it accepts inner
// secure connections, multiplexes them, and for each stream dials the requested
// target and pipes. Test tool (raw inner, no skin); the skin wraps this the same
// way it wraps the echo server.
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/tanur-net/tanur/inner"
	"github.com/tanur-net/tanur/recipe"
	"github.com/tanur-net/tanur/tunnel"
)

func main() {
	addr := flag.String("addr", "0.0.0.0:9500", "listen address")
	keyB64 := flag.String("key", "", "base64 static private key; empty = generate")
	flag.Parse()

	static, err := loadOrGen(*keyB64)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprintln(os.Stderr, "server public key:", base64.StdEncoding.EncodeToString(static.Public))

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(ln.Addr().String())
	r := devRecipe()
	for {
		raw, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go serve(raw, static, r)
	}
}

func serve(raw net.Conn, static inner.StaticKey, r recipe.Recipe) {
	defer raw.Close()
	if tc, ok := raw.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	conn, err := inner.Server(raw, static, r)
	if err != nil {
		return
	}
	m, err := inner.ServerMux(conn)
	if err != nil {
		return
	}
	tunnel.ServeExit(m, 15*time.Second, log.Printf)
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
