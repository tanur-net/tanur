// SPDX-License-Identifier: MPL-2.0

// Command tanur-cli dials a tanur-server over the inner secure channel, sends a
// payload, reads the echo, and reports handshake time, round-trip time and
// throughput. Local/test tool only.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/tanur-net/tanur/inner"
	"github.com/tanur-net/tanur/recipe"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:9000", "server address host:port")
	pubB64 := flag.String("pub", "", "base64 server public key (required)")
	size := flag.Int("size", 64*1024, "bytes to send and echo back")
	flag.Parse()

	if *pubB64 == "" {
		log.Fatal("tanur-cli: -pub (server public key) is required")
	}
	pub, err := base64.StdEncoding.DecodeString(*pubB64)
	if err != nil {
		log.Fatal("bad -pub:", err)
	}

	tcpStart := time.Now()
	raw, err := net.DialTimeout("tcp", *addr, 15*time.Second)
	if err != nil {
		log.Fatal("dial:", err)
	}
	defer raw.Close()
	if tc, ok := raw.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	tcpMS := time.Since(tcpStart).Milliseconds()

	hsStart := time.Now()
	conn, err := inner.Client(raw, pub, devRecipe())
	if err != nil {
		log.Fatal("handshake:", err)
	}
	hsMS := time.Since(hsStart).Milliseconds()

	// Build a random payload so compression/caching cannot flatter the result.
	payload := make([]byte, *size)
	rand.Read(payload)

	rtStart := time.Now()
	go func() {
		if _, werr := conn.Write(payload); werr != nil {
			log.Println("write:", werr)
		}
	}()

	got := make([]byte, 0, *size)
	buf := make([]byte, 32*1024)
	_ = raw.SetReadDeadline(time.Now().Add(60 * time.Second))
	for len(got) < *size {
		n, rerr := conn.Read(buf)
		got = append(got, buf[:n]...)
		if rerr != nil {
			if rerr == io.EOF {
				break
			}
			log.Fatal("read:", rerr)
		}
	}
	rtMS := time.Since(rtStart).Milliseconds()

	ok := bytes.Equal(got, payload)
	// Throughput over the round trip: 2*size bytes moved (up + down).
	var mbps float64
	if rtMS > 0 {
		mbps = float64(2*len(got)) * 8 / 1e6 / (float64(rtMS) / 1000)
	}
	fmt.Printf("addr=%s\n", *addr)
	fmt.Printf("tcp_connect=%dms  handshake=%dms  roundtrip=%dms\n", tcpMS, hsMS, rtMS)
	fmt.Printf("echo_bytes=%d/%d  match=%v  throughput=%.2f Mbit/s (up+down)\n",
		len(got), *size, ok, mbps)
	if ok {
		fmt.Println("RESULT: OK")
	} else {
		fmt.Println("RESULT: MISMATCH")
	}
}

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
