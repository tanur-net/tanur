// SPDX-License-Identifier: MPL-2.0

// Command tanur-server is a minimal echo server over the inner secure channel,
// for local end-to-end testing before the TLS skin and real deployment exist.
// It is NOT the production server; it has no skin and no auth beyond the
// handshake. It exists to exercise inner + shaper over real sockets.
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/tanur-net/tanur/inner"
	"github.com/tanur-net/tanur/recipe"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "listen address")
	keyB64 := flag.String("key", "", "base64 server static private key; empty = generate and print")
	flag.Parse()

	static, err := loadOrGenKey(*keyB64)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprintln(os.Stderr, "server public key:", base64.StdEncoding.EncodeToString(static.Public))

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(ln.Addr().String()) // stdout: the chosen address, for scripts
	r := devRecipe()

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go serve(c, static, r)
	}
}

func serve(raw net.Conn, static inner.StaticKey, r recipe.Recipe) {
	defer raw.Close()
	if tc, ok := raw.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	conn, err := inner.Server(raw, static, r)
	if err != nil {
		log.Println("handshake:", err)
		return
	}
	// Echo everything back through the shaped channel.
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			if _, werr := conn.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Println("read:", err)
			}
			return
		}
	}
}

func loadOrGenKey(b64 string) (inner.StaticKey, error) {
	if b64 == "" {
		return inner.GenerateStatic()
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return inner.StaticKey{}, err
	}
	return inner.StaticFromPrivate(raw)
}

// devRecipe is a fixed local recipe for the echo server.
func devRecipe() recipe.Recipe {
	return recipe.Recipe{
		ID:      "dev-local",
		Version: 1,
		Skin:    recipe.SkinParams{ServerName: "localhost", ALPN: []string{"http/1.1"}},
		Frame:   recipe.IntDist{Min: 512, Max: 8192},
		Burst:   recipe.IntDist{Min: 16, Max: 64},
		Gap:     recipe.IntDist{Min: 0, Max: 10},
		Pause:   recipe.IntDist{Min: 0, Max: 0},
		Pad:     recipe.IntDist{Min: 0, Max: 128},
		Session: recipe.SessionBounds{MaxSeconds: 600, MaxBytes: 200 << 20},
	}
}
