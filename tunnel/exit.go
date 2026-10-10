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
	d := net.Dialer{Timeout: dialTimeout}
	up, err := d.Dial("tcp", addr)
	if err != nil {
		logf("exit dial %s: %v", addr, err)
		st.Close()
		return
	}
	if tc, ok := up.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	pipe(st, up)
}

// compile-time check that *inner.Mux is a StreamAccepter.
var _ StreamAccepter = (*inner.Mux)(nil)
