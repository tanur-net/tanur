// SPDX-License-Identifier: MPL-2.0

package tunnel

import (
	"bytes"
	"crypto/subtle"
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
// all a local loopback proxy on a device the app alone controls needs.
func SocksServer(ln net.Listener, open StreamOpener) error {
	return socksServe(ln, open, "", "", nil)
}

// SocksServerMetered is SocksServer (with optional auth) that also counts the
// application bytes it carries into m, for a traffic readout. m may be nil.
func SocksServerMetered(ln net.Listener, open StreamOpener, user, pass string, m *Meter) error {
	return socksServe(ln, open, user, pass, m)
}

// SocksServerAuth is SocksServer with mandatory username/password login
// (RFC 1929). It exists for host apps that put more than our own tun2socks in
// front of the port: on Android the data path is hev-socks5-tunnel, which the
// host's VPN service configures with a fresh per-session username and password so
// that no other app on the phone can use the open loopback SOCKS port. hev then
// offers method 0x02 and logs in; a plain no-auth server would be a port any
// app could borrow. user must be non-empty; with an empty user, use SocksServer.
func SocksServerAuth(ln net.Listener, open StreamOpener, user, pass string) error {
	return socksServe(ln, open, user, pass, nil)
}

func socksServe(ln net.Listener, open StreamOpener, user, pass string, m *Meter) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go serveSocksConn(c, open, user, pass, m)
	}
}

func serveSocksConn(c net.Conn, open StreamOpener, user, pass string, m *Meter) {
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	cmd, target, err := socksHandshake(c, user, pass)
	if err != nil {
		c.Close()
		return
	}
	if cmd == 0x03 {
		// UDP ASSOCIATE. The TCP connection stays open as the control channel:
		// the UDP relay lives as long as it does, and tearing it down closes
		// the relay. This is what carries DNS (and QUIC) for a TUN-based VPN,
		// where the client resolves names itself over UDP; without it a device
		// tunnel comes up and carries nothing because no name ever resolves.
		serveUDPAssociate(c, open, m)
		c.Close()
		return
	}
	// CONNECT.
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
	meteredPipe(c, st, m)
}

// meteredPipe is pipe with byte counting for the traffic readout: bytes from the
// client (c -> st) are upload, bytes to the client (st -> c) are download. With
// a nil meter it is an ordinary pipe.
func meteredPipe(c, st io.ReadWriteCloser, m *Meter) {
	if m == nil {
		pipe(c, st)
		return
	}
	done := make(chan struct{}, 2)
	go func() { io.Copy(countWriter{st, m.addUp}, c); done <- struct{}{} }()
	go func() { io.Copy(countWriter{c, m.addDown}, st); done <- struct{}{} }()
	<-done
	c.Close()
	st.Close()
}

// socksHandshake performs the SOCKS5 greeting and request parsing and returns
// the command (0x01 CONNECT or 0x03 UDP ASSOCIATE) and the requested
// "host:port". With a non-empty user it requires RFC 1929 username/password
// login and rejects a client that will not do it; with an empty user it selects
// no-auth, the loopback default. For UDP ASSOCIATE the returned address is the
// one in the request (often 0.0.0.0:0) and the caller ignores it.
func socksHandshake(c net.Conn, user, pass string) (byte, string, error) {
	// Greeting: VER NMETHODS METHODS...
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return 0, "", err
	}
	if head[0] != 0x05 {
		return 0, "", fmt.Errorf("socks: unsupported version %d", head[0])
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return 0, "", err
	}
	if user != "" {
		// Require username/password (0x02). If the client did not offer it,
		// tell it no acceptable method (0xFF) and stop.
		if !bytes.Contains(methods, []byte{0x02}) {
			c.Write([]byte{0x05, 0xFF})
			return 0, "", fmt.Errorf("socks: client offered no username/password method")
		}
		if _, err := c.Write([]byte{0x05, 0x02}); err != nil {
			return 0, "", err
		}
		if err := socksUserPass(c, user, pass); err != nil {
			return 0, "", err
		}
	} else {
		// Reply: VER METHOD(0x00 = no auth)
		if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
			return 0, "", err
		}
	}

	// Request: VER CMD RSV ATYP ADDR PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return 0, "", err
	}
	if req[0] != 0x05 {
		return 0, "", fmt.Errorf("socks: bad request version")
	}
	// 0x01 CONNECT and 0x03 UDP ASSOCIATE are supported; 0x02 BIND is not.
	if req[1] != 0x01 && req[1] != 0x03 {
		socksReply(c, 0x07) // command not supported
		return 0, "", fmt.Errorf("socks: unsupported command %d", req[1])
	}

	host, err := readSocksAddr(c, req[3])
	if err != nil {
		socksReply(c, 0x08) // address type not supported
		return 0, "", err
	}

	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return 0, "", err
	}
	port := binary.BigEndian.Uint16(pb)
	return req[1], net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// readSocksAddr reads one SOCKS5 address of the given ATYP from r and returns it
// as a host string (IPv4/IPv6 literal, or a domain name).
func readSocksAddr(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	case 0x03: // domain
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return "", err
		}
		b := make([]byte, l[0])
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return string(b), nil
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		return net.IP(b).String(), nil
	default:
		return "", fmt.Errorf("socks: bad atyp %d", atyp)
	}
}

// socksUserPass runs the RFC 1929 username/password sub-negotiation as the
// server. The client sends VER(0x01) ULEN uname PLEN passwd; we compare in
// constant time and reply VER(0x01) STATUS, where 0x00 is success and any
// non-zero is failure (the client must then close).
func socksUserPass(c net.Conn, user, pass string) error {
	h := make([]byte, 2)
	if _, err := io.ReadFull(c, h); err != nil {
		return err
	}
	if h[0] != 0x01 {
		return fmt.Errorf("socks: bad auth version %d", h[0])
	}
	uname := make([]byte, h[1])
	if _, err := io.ReadFull(c, uname); err != nil {
		return err
	}
	pl := make([]byte, 1)
	if _, err := io.ReadFull(c, pl); err != nil {
		return err
	}
	passwd := make([]byte, pl[0])
	if _, err := io.ReadFull(c, passwd); err != nil {
		return err
	}
	ok := subtle.ConstantTimeCompare(uname, []byte(user)) == 1 &&
		subtle.ConstantTimeCompare(passwd, []byte(pass)) == 1
	if !ok {
		c.Write([]byte{0x01, 0x01}) // failure
		return fmt.Errorf("socks: bad username/password")
	}
	if _, err := c.Write([]byte{0x01, 0x00}); err != nil { // success
		return err
	}
	return nil
}

// socksReply writes a SOCKS5 reply with the given status and a zero BND.ADDR.
func socksReply(c net.Conn, status byte) error {
	_, err := c.Write([]byte{0x05, status, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}
