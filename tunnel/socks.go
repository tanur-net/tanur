// SPDX-License-Identifier: MPL-2.0

package tunnel

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

// StreamOpener is the client side of a mux: it opens a new logical stream.
// *inner.Mux satisfies it.
type StreamOpener interface {
	Open() (io.ReadWriteCloser, error)
}

// SocksServer runs a minimal SOCKS5 proxy on ln. For each accepted SOCKS
// connection it parses the CONNECT target, opens one mux stream, sends the
// target header, and pipes. This is what apps (browser, curl --socks5) point at.
//
// Only the SOCKS5 CONNECT command is supported, with no authentication, which is
// all a local loopback proxy needs.
func SocksServer(ln net.Listener, open StreamOpener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go serveSocksConn(c, open)
	}
}

func serveSocksConn(c net.Conn, open StreamOpener) {
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	target, err := socksHandshake(c)
	if err != nil {
		c.Close()
		return
	}
	st, err := open.Open()
	if err != nil {
		// 0x01 = general SOCKS server failure
		socksReply(c, 0x01)
		c.Close()
		return
	}
	if err := writeTarget(st, target); err != nil {
		socksReply(c, 0x01)
		st.Close()
		c.Close()
		return
	}
	// 0x00 = succeeded. We reply success optimistically; if the far dial fails
	// the stream simply closes, which the app sees as a dropped connection.
	if err := socksReply(c, 0x00); err != nil {
		st.Close()
		c.Close()
		return
	}
	pipe(c, st)
}

// socksHandshake performs the SOCKS5 greeting and CONNECT request parsing and
// returns the requested "host:port".
func socksHandshake(c net.Conn) (string, error) {
	// Greeting: VER NMETHODS METHODS...
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return "", err
	}
	if head[0] != 0x05 {
		return "", fmt.Errorf("socks: unsupported version %d", head[0])
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return "", err
	}
	// Reply: VER METHOD(0x00 = no auth)
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return "", err
	}

	// Request: VER CMD RSV ATYP ADDR PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return "", err
	}
	if req[0] != 0x05 {
		return "", fmt.Errorf("socks: bad request version")
	}
	if req[1] != 0x01 { // CONNECT only
		socksReply(c, 0x07) // command not supported
		return "", fmt.Errorf("socks: unsupported command %d", req[1])
	}

	var host string
	switch req[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 0x03: // domain
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return "", err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		host = string(b)
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	default:
		socksReply(c, 0x08) // address type not supported
		return "", fmt.Errorf("socks: bad atyp %d", req[3])
	}

	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(pb)
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// socksReply writes a SOCKS5 reply with the given status and a zero BND.ADDR.
func socksReply(c net.Conn, status byte) error {
	_, err := c.Write([]byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}
