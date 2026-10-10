// SPDX-License-Identifier: MPL-2.0

package skin

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
)

// prefixConn returns an io.ReadWriteCloser that first yields n bytes still
// buffered in br, then reads live from tc. Writes and Close go to tc. This is
// needed because http.ReadRequest may have buffered bytes past the request that
// actually belong to the inner channel.
func prefixConn(tc net.Conn, n int, br *bufio.Reader) io.ReadWriteCloser {
	var head []byte
	if n > 0 {
		head, _ = br.Peek(n)
		cp := make([]byte, len(head))
		copy(cp, head)
		head = cp
	}
	return &joinConn{head: head, tc: tc}
}

type joinConn struct {
	head []byte
	off  int
	tc   net.Conn
}

func (j *joinConn) Read(p []byte) (int, error) {
	if j.off < len(j.head) {
		n := copy(p, j.head[j.off:])
		j.off += n
		return n, nil
	}
	return j.tc.Read(p)
}

func (j *joinConn) Write(p []byte) (int, error) { return j.tc.Write(p) }
func (j *joinConn) Close() error                { return j.tc.Close() }

// respWriter is a minimal http.ResponseWriter that emits a single HTTP/1.1
// response directly onto a connection, enough to serve the cover site.
type respWriter struct {
	conn    net.Conn
	header  http.Header
	status  int
	body    []byte
	written bool
}

func (w *respWriter) Header() http.Header { return w.header }

func (w *respWriter) WriteHeader(status int) {
	if w.written {
		return
	}
	w.status = status
	w.written = true
}

func (w *respWriter) Write(b []byte) (int, error) {
	if !w.written {
		w.WriteHeader(200)
	}
	w.body = append(w.body, b...)
	return len(b), nil
}

func (w *respWriter) flush() {
	if !w.written {
		w.WriteHeader(200)
	}
	fmt.Fprintf(w.conn, "HTTP/1.1 %d %s\r\n", w.status, http.StatusText(w.status))
	w.header.Set("Content-Length", fmt.Sprintf("%d", len(w.body)))
	if w.header.Get("Content-Type") == "" {
		w.header.Set("Content-Type", "text/html; charset=utf-8")
	}
	keys := make([]string, 0, len(w.header))
	for k := range w.header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range w.header[k] {
			fmt.Fprintf(w.conn, "%s: %s\r\n", k, v)
		}
	}
	io.WriteString(w.conn, "\r\n")
	w.conn.Write(w.body)
}
