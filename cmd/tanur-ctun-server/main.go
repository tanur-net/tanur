// SPDX-License-Identifier: MPL-2.0

// Command tanur-ctun-server is the production-shaped server: the tunnel exit,
// carried inside HTTP so it can sit behind a CDN. It serves a cover site on "/"
// and the carrier on a secret path. Put a real TLS cert / a CDN in front in
// production; this listens plain HTTP so a CDN (which terminates TLS) can
// forward to it, or so it can be tested directly.
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/tanur-net/tanur/carrier"
	"github.com/tanur-net/tanur/inner"
	"github.com/tanur-net/tanur/recipe"
	"github.com/tanur-net/tanur/tunnel"
)

func main() {
	addr := flag.String("addr", "0.0.0.0:8080", "HTTP listen address (CDN forwards here)")
	path := flag.String("path", "/4dc37c94", "secret carrier path")
	keyB64 := flag.String("key", "", "base64 static private key; empty = generate")
	flag.Parse()

	static, err := loadOrGen(*keyB64)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprintln(os.Stderr, "server public key:", base64.StdEncoding.EncodeToString(static.Public))
	r := devRecipe()

	cs := &carrier.HTTPServer{Handle: func(rw io.ReadWriteCloser) {
		conn, err := inner.Server(rw, static, r)
		if err != nil {
			return
		}
		m, err := inner.ServerMux(conn)
		if err != nil {
			return
		}
		tunnel.ServeExit(m, 15*time.Second, log.Printf)
	}}

	mux := http.NewServeMux()
	mux.Handle(*path, cs)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Cover site for browsers / probes.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, "<!doctype html><title>Welcome</title><h1>It works</h1>\n")
	})

	fmt.Println(*addr + *path)
	log.Fatal(http.ListenAndServe(*addr, mux))
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
