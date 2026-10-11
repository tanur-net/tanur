// SPDX-License-Identifier: MPL-2.0

package tunnel

import (
	"io"
	"sync/atomic"
)

// Meter counts application bytes carried by the local SOCKS proxy: Up is what
// the device sent out, Down is what it received. It is measured at the SOCKS
// boundary (plaintext app bytes), not on the shaped inner channel, so the
// numbers match what a user's apps actually moved. A nil *Meter counts nothing,
// so the data path is unchanged when no meter is wired in.
type Meter struct {
	up   atomic.Int64
	down atomic.Int64
}

// Up returns total bytes sent from the device.
func (m *Meter) Up() int64 {
	if m == nil {
		return 0
	}
	return m.up.Load()
}

// Down returns total bytes received by the device.
func (m *Meter) Down() int64 {
	if m == nil {
		return 0
	}
	return m.down.Load()
}

func (m *Meter) addUp(n int64) {
	if m != nil {
		m.up.Add(n)
	}
}

func (m *Meter) addDown(n int64) {
	if m != nil {
		m.down.Add(n)
	}
}

// countWriter counts the bytes written through it into one direction of a Meter.
type countWriter struct {
	w   io.Writer
	add func(int64)
}

func (c countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if n > 0 {
		c.add(int64(n))
	}
	return n, err
}
