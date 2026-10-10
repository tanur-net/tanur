// SPDX-License-Identifier: MPL-2.0

// Command tanur-skin-cli dials a tanur-skin-server over the TLS skin, presents
// the door, runs the inner echo, and reports timing/throughput. Test tool.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/tanur-net/tanur/recipe"
	"github.com/tanur-net/tanur/skin"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:443", "server host:port")
	sni := flag.String("sni", "localhost", "SNI to present")
	pubB64 := flag.String("pub", "", "base64 server public key (required)")
	door := flag.String("door", "tanur-test-door", "shared door secret")
	size := flag.Int("size", 65536, "bytes to echo")
	echB64 := flag.String("ech", "", "base64 ECHConfigList; when set the ClientHello is encrypted (ECH)")
	flag.Parse()

	if *pubB64 == "" {
		log.Fatal("tanur-skin-cli: -pub is required")
	}
	pub, err := base64.StdEncoding.DecodeString(*pubB64)
	if err != nil {
		log.Fatal("bad -pub:", err)
	}

	r := devRecipe(*sni)
	r.Skin.ECHConfigList = *echB64
	if err := r.Validate(); err != nil {
		log.Fatal("recipe:", err)
	}
	// The recipe carries ECH as base64; decode it for the skin client. Validate
	// above already proved it decodes.
	ech, _ := base64.StdEncoding.DecodeString(r.Skin.ECHConfigList)

	cc := &skin.ClientConfig{
		Addr: *addr,
		// Self-signed cert in the first bring-up: skip verification. A real
		// deployment uses a real cert and verifies it.
		TLS:           &tls.Config{ServerName: *sni, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		ServerPub:     pub,
		Recipe:        r,
		DoorSecret:    *door,
		ECHConfigList: ech,
	}

	start := time.Now()
	conn, err := cc.Dial()
	if err != nil {
		log.Fatal("dial/handshake:", err)
	}
	defer conn.Close()
	setupMS := time.Since(start).Milliseconds()

	payload := make([]byte, *size)
	rand.Read(payload)
	rt := time.Now()
	go conn.Write(payload)
	got := make([]byte, 0, *size)
	buf := make([]byte, 32*1024)
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
	rtMS := time.Since(rt).Milliseconds()
	ok := bytes.Equal(got, payload)
	var mbps float64
	if rtMS > 0 {
		mbps = float64(2*len(got)) * 8 / 1e6 / (float64(rtMS) / 1000)
	}
	fmt.Printf("addr=%s sni=%s\n", *addr, *sni)
	fmt.Printf("setup(tls+door+handshake)=%dms  roundtrip=%dms  throughput=%.2f Mbit/s\n", setupMS, rtMS, mbps)
	fmt.Printf("echo=%d/%d match=%v\n", len(got), *size, ok)
	if ok {
		fmt.Println("RESULT: OK")
	} else {
		fmt.Println("RESULT: MISMATCH")
	}
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
