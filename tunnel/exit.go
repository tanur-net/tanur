// SPDX-License-Identifier: MPL-2.0

package tunnel

import (
	"io"
	"net"
	"time"

	"github.com/tanur-net/tanur/inner"
)

// StreamAccepter is the server side of a mux: it yields the next logical stream.
// *inner.Mux satisfies it.
type StreamAccepter interface {
	Accept() (io.ReadWriteCloser, error)
}

// ServeExit is the server's job: for each logical stream the client opens, read
// the target it wants, dial it, and pipe bytes. This makes the server a real
// exit to the internet. It returns when the mux ends.
//
// dialTimeout bounds each outbound dial. logf may be nil.
func ServeExit(m StreamAccepter, dialTimeout time.Duration, logf func(string, ...any)) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	for {
		st, err := m.Accept()
		if err != nil {
			return err
		}
		go handleExitStream(st, dialTimeout, logf)
	}
}

func handleExitStream(st io.ReadWriteCloser, dialTimeout time.Duration, logf func(string, ...any)) {
	addr, err := readTarget(st)
	if err != nil {
		st.Close()
		return
	}
	isUDP, hostPort := parseTarget(addr)
	if isUDP {
		exitUDP(st, hostPort, logf)
		return
	}
	d := net.Dialer{Timeout: dialTimeout}
	up, err := d.Dial("tcp", hostPort)
	if err != nil {
		logf("exit dial %s: %v", hostPort, err)
		st.Close()
		return
	}
	if tc, ok := up.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	pipe(st, up)
}

// exitUDP serves a UDP target stream: it dials the UDP destination and relays
// length-prefixed datagrams between the mux stream and that socket. The socket
// is closed when the stream ends or after udpIdle without a datagram, so a DNS
// lookup's one round trip does not hold a socket open indefinitely.
func exitUDP(st io.ReadWriteCloser, hostPort string, logf func(string, ...any)) {
	defer st.Close()
	up, err := net.Dial("udp", hostPort)
	if err != nil {
		logf("exit udp dial %s: %v", hostPort, err)
		return
	}
	defer up.Close()
	relayUDPOverStream(st, up.(*net.UDPConn))
}

// compile-time check that *inner.Mux is a StreamAccepter.
var _ StreamAccepter = (*inner.Mux)(nil)
