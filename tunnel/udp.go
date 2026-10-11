// SPDX-License-Identifier: MPL-2.0

package tunnel

import (
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// UDP support turns Tanur from a TCP-only forwarder into something a TUN-based
// device VPN can actually use. On a phone the client resolves names itself, over
// UDP to a DNS server, before it opens any TCP flow; tun2socks (hev-socks5-tunnel)
// carries that DNS as SOCKS5 UDP ASSOCIATE. Without UDP the tunnel comes up and
// carries nothing, because no name ever resolves — the exact 0-byte symptom seen
// on the first Android bring-up.
//
// The design keeps UDP inside the same multiplexed, shaped inner channel as TCP:
// each UDP destination becomes one mux stream whose first bytes are the target
// header (prefixed "udp:"), after which datagrams travel length-prefixed
// ([2 bytes len][datagram]). A connected UDP socket at the exit speaks to the
// real destination. Datagrams to the same destination share a stream; the reply
// pump routes answers back to the client's source address.

// udpIdle bounds how long an exit UDP socket is held with no traffic. A DNS
// lookup is one round trip; QUIC flows refresh it. Short enough not to hoard
// sockets, long enough to serve a keep-alive-less exchange.
const udpIdle = 60 * time.Second

// maxDatagram caps a single relayed datagram. 64 KiB covers the largest UDP
// payload; anything larger is malformed for our purposes.
const maxDatagram = 64 * 1024

// serveUDPAssociate handles a SOCKS5 UDP ASSOCIATE. ctrl is the TCP control
// connection: it stays open for the life of the association, and its close tears
// the relay down. open provides mux streams to the exit.
func serveUDPAssociate(ctrl net.Conn, open StreamOpener, m *Meter) {
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		socksReply(ctrl, 0x01)
		return
	}
	defer uc.Close()

	// Tell the client where to send its datagrams.
	if err := socksReplyUDPAddr(ctrl, uc.LocalAddr().(*net.UDPAddr)); err != nil {
		return
	}

	a := &udpAssoc{uc: uc, open: open, meter: m, streams: map[string]io.ReadWriteCloser{}}
	defer a.closeAll()

	// The control connection carries no data; when it closes, stop the relay.
	go func() {
		io.Copy(io.Discard, ctrl)
		uc.SetReadDeadline(time.Now())
	}()

	buf := make([]byte, maxDatagram)
	for {
		n, src, err := uc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		target, data, ok := parseUDPDatagram(buf[:n])
		if !ok {
			continue
		}
		a.setClient(src)
		a.meter.addUp(int64(len(data)))
		a.send(target, data)
	}
}

// udpAssoc is one UDP ASSOCIATE: a client UDP socket, and one mux stream per
// destination it talks to.
type udpAssoc struct {
	uc    *net.UDPConn
	open  StreamOpener
	meter *Meter

	mu      sync.Mutex
	client  *net.UDPAddr
	streams map[string]io.ReadWriteCloser
}

func (a *udpAssoc) setClient(src *net.UDPAddr) {
	a.mu.Lock()
	a.client = src
	a.mu.Unlock()
}

func (a *udpAssoc) clientAddr() *net.UDPAddr {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.client
}

// send forwards one datagram to target, opening a stream for that destination on
// first use. It is called only from the single ReadFromUDP loop, so writes to a
// given stream are serialized.
func (a *udpAssoc) send(target string, data []byte) {
	a.mu.Lock()
	st := a.streams[target]
	a.mu.Unlock()
	if st == nil {
		var err error
		st, err = a.open.Open()
		if err != nil {
			return
		}
		if err := writeTarget(st, udpTarget(target)); err != nil {
			st.Close()
			return
		}
		a.mu.Lock()
		a.streams[target] = st
		a.mu.Unlock()
		go a.pump(target, st)
	}
	if err := writeFrame(st, data); err != nil {
		a.remove(target)
	}
}

// pump reads datagrams coming back on st and hands them to the client, tagged
// with target as their source so the client matches them to its query.
func (a *udpAssoc) pump(target string, st io.ReadWriteCloser) {
	for {
		data, err := readFrame(st)
		if err != nil {
			a.remove(target)
			return
		}
		dst := a.clientAddr()
		if dst == nil {
			continue
		}
		a.meter.addDown(int64(len(data)))
		a.uc.WriteToUDP(buildUDPDatagram(target, data), dst)
	}
}

func (a *udpAssoc) remove(target string) {
	a.mu.Lock()
	st := a.streams[target]
	delete(a.streams, target)
	a.mu.Unlock()
	if st != nil {
		st.Close()
	}
}

func (a *udpAssoc) closeAll() {
	a.mu.Lock()
	streams := a.streams
	a.streams = map[string]io.ReadWriteCloser{}
	a.mu.Unlock()
	for _, st := range streams {
		st.Close()
	}
}

// relayUDPOverStream is the exit side: it copies length-prefixed datagrams
// between the mux stream and a connected UDP socket, closing when the stream
// ends or the socket is idle for udpIdle.
func relayUDPOverStream(st io.ReadWriteCloser, uc *net.UDPConn) {
	done := make(chan struct{}, 2)
	// stream -> udp
	go func() {
		for {
			data, err := readFrame(st)
			if err != nil {
				done <- struct{}{}
				return
			}
			if _, err := uc.Write(data); err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	// udp -> stream
	go func() {
		buf := make([]byte, maxDatagram)
		for {
			uc.SetReadDeadline(time.Now().Add(udpIdle))
			n, err := uc.Read(buf)
			if err != nil {
				done <- struct{}{}
				return
			}
			if err := writeFrame(st, buf[:n]); err != nil {
				done <- struct{}{}
				return
			}
		}
	}()
	<-done
}

// writeFrame writes one length-prefixed datagram in a single Write, so it lands
// as one contiguous region in the shaped stream and cannot interleave with
// another writer's frame.
func writeFrame(w io.Writer, data []byte) error {
	if len(data) > maxDatagram {
		data = data[:maxDatagram]
	}
	buf := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(data)))
	copy(buf[2:], data)
	_, err := w.Write(buf)
	return err
}

// readFrame reads one length-prefixed datagram.
func readFrame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// parseUDPDatagram reads a SOCKS5 UDP request datagram (RSV RSV FRAG ATYP ADDR
// PORT DATA) and returns its destination "host:port" and payload. A fragmented
// datagram (FRAG != 0) is unsupported and dropped.
func parseUDPDatagram(p []byte) (target string, data []byte, ok bool) {
	if len(p) < 4 || p[2] != 0 {
		return "", nil, false
	}
	off := 4
	var host string
	switch p[3] {
	case 0x01:
		if len(p) < off+4+2 {
			return "", nil, false
		}
		host = net.IP(p[off : off+4]).String()
		off += 4
	case 0x04:
		if len(p) < off+16+2 {
			return "", nil, false
		}
		host = net.IP(p[off : off+16]).String()
		off += 16
	case 0x03:
		if len(p) < off+1 {
			return "", nil, false
		}
		l := int(p[off])
		off++
		if len(p) < off+l+2 {
			return "", nil, false
		}
		host = string(p[off : off+l])
		off += l
	default:
		return "", nil, false
	}
	port := binary.BigEndian.Uint16(p[off : off+2])
	off += 2
	return net.JoinHostPort(host, strconv.Itoa(int(port))), p[off:], true
}

// buildUDPDatagram wraps a reply payload in a SOCKS5 UDP datagram whose address
// is target, so the client reads the answer as coming from the destination it
// sent to.
func buildUDPDatagram(target string, data []byte) []byte {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return nil
	}
	port, _ := strconv.Atoi(portStr)
	out := []byte{0, 0, 0} // RSV RSV FRAG
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			out = append(out, 0x01)
			out = append(out, ip4...)
		} else {
			out = append(out, 0x04)
			out = append(out, ip.To16()...)
		}
	} else {
		out = append(out, 0x03, byte(len(host)))
		out = append(out, host...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	out = append(out, pb[:]...)
	return append(out, data...)
}

// socksReplyUDPAddr replies to a UDP ASSOCIATE with the relay's bound address.
func socksReplyUDPAddr(c net.Conn, addr *net.UDPAddr) error {
	out := []byte{0x05, 0x00, 0x00}
	if ip4 := addr.IP.To4(); ip4 != nil {
		out = append(out, 0x01)
		out = append(out, ip4...)
	} else {
		out = append(out, 0x04)
		out = append(out, addr.IP.To16()...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(addr.Port))
	out = append(out, pb[:]...)
	_, err := c.Write(out)
	return err
}
