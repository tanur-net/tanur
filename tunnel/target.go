// SPDX-License-Identifier: MPL-2.0

// Package tunnel turns the secure, multiplexed inner channel into a real
// forwarding tunnel: the client exposes a local SOCKS5 proxy, each SOCKS
// connection becomes one mux stream, and the server dials the requested target
// and pipes bytes. This is the step that makes Tanur carry real traffic rather
// than echo. A full device VPN (TUN) builds on this same data path later.
package tunnel

import (
	"encoding/binary"
	"errors"
	"io"
)

// Each mux stream opens with a target header: the destination "host:port" the
// client wants reached. It is sent once, first thing, inside the already
// encrypted stream.
//
//	[2 bytes: length N][N bytes: "host:port"]

const maxTargetLen = 1 << 10

// ErrBadTarget is returned for a malformed or oversize target header.
var ErrBadTarget = errors.New("tunnel: malformed target header")

// writeTarget sends the target header on a stream.
func writeTarget(w io.Writer, addr string) error {
	if len(addr) == 0 || len(addr) > maxTargetLen {
		return ErrBadTarget
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(addr)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := io.WriteString(w, addr)
	return err
}

// readTarget reads the target header from a stream.
func readTarget(r io.Reader) (string, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return "", err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	if n == 0 || n > maxTargetLen {
		return "", ErrBadTarget
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// pipe copies a<->b until either side ends, then closes both.
func pipe(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
	a.Close()
	b.Close()
}
