package cf

import (
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type streamConn struct {
	tc *Client
	s  *session

	mu            sync.Mutex
	readBuf       []byte
	closed        bool
	readDeadline  time.Time
	writeDeadline time.Time
}

func newStreamConn(tc *Client, s *session) net.Conn {
	return &streamConn{tc: tc, s: s}
}

func (c *streamConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, io.EOF
	}
	deadline := c.readDeadline
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()

	var timer *time.Timer
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		timer = time.NewTimer(d)
		timeout = timer.C
		defer timer.Stop()
	}

	select {
	case b := <-c.s.readCh:
		n := copy(p, b)
		if n < len(b) {
			c.mu.Lock()
			c.readBuf = append(c.readBuf[:0], b[n:]...)
			c.mu.Unlock()
		}
		return n, nil
	case <-c.s.done:
		return 0, c.s.getErr()
	case <-c.tc.closed:
		return 0, io.EOF
	case <-timeout:
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *streamConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	deadline := c.writeDeadline
	c.mu.Unlock()

	payload := make([]byte, len(p))
	copy(payload, p)
	var timeout time.Duration
	if !deadline.IsZero() {
		timeout = time.Until(deadline)
		if timeout <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
	}
	if err := c.tc.writeFrameWithTimeout(Frame{Type: TypeData, ConnID: c.s.id, Nonce: c.tc.nonceGen.Next(), Payload: payload}, nil, timeout); err != nil {
		if timeout > 0 && errors.Is(err, os.ErrDeadlineExceeded) {
			return 0, os.ErrDeadlineExceeded
		}
		return 0, err
	}
	return len(p), nil
}

func (c *streamConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	_ = c.tc.writeFrame(Frame{Type: TypeClose, ConnID: c.s.id, Nonce: c.tc.nonceGen.Next()})
	c.tc.removeSession(c.s.id, net.ErrClosed)
	return nil
}

func (c *streamConn) LocalAddr() net.Addr  { return dummyAddr("cf-local") }
func (c *streamConn) RemoteAddr() net.Addr { return dummyAddr(c.s.target) }
func (c *streamConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

func (c *streamConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return nil
}

func (c *streamConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

type dummyAddr string

func (d dummyAddr) Network() string { return "cf" }
func (d dummyAddr) String() string  { return string(d) }

type packetConnCF struct {
	tc *Client
	s  *udpSession

	mu            sync.Mutex
	closed        bool
	readDeadline  time.Time
	writeDeadline time.Time

	raddr net.Addr
}

func newPacketConnCF(tc *Client, s *udpSession) net.PacketConn {
	return &packetConnCF{tc: tc, s: s, raddr: parseUDPAddr(s.target)}
}

func parseUDPAddr(target string) net.Addr {
	if strings.HasPrefix(target, "[") || strings.Count(target, ":") == 1 {
		if a, err := net.ResolveUDPAddr("udp", target); err == nil {
			return a
		}
	}
	if host, port, err := net.SplitHostPort(target); err == nil {
		if a, e := net.ResolveUDPAddr("udp", net.JoinHostPort(host, port)); e == nil {
			return a
		}
	}
	return dummyAddr(target)
}

func (c *packetConnCF) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, nil, net.ErrClosed
	}
	deadline := c.readDeadline
	raddr := c.raddr
	c.mu.Unlock()

	var timer *time.Timer
	var timeout <-chan time.Time
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return 0, nil, os.ErrDeadlineExceeded
		}
		timer = time.NewTimer(d)
		timeout = timer.C
		defer timer.Stop()
	}

	select {
	case pkt := <-c.s.readCh:
		n := copy(p, pkt.b)
		return n, raddr, nil
	case <-c.s.done:
		return 0, nil, c.s.getErr()
	case <-c.tc.closed:
		return 0, nil, io.EOF
	case <-timeout:
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (c *packetConnCF) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	deadline := c.writeDeadline
	c.mu.Unlock()

	payload := make([]byte, len(p))
	copy(payload, p)
	var timeout time.Duration
	if !deadline.IsZero() {
		timeout = time.Until(deadline)
		if timeout <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
	}
	if err := c.tc.writeFrameWithTimeout(Frame{Type: TypeUDPData, ConnID: c.s.id, Nonce: c.tc.nonceGen.Next(), Payload: payload}, nil, timeout); err != nil {
		if timeout > 0 && errors.Is(err, os.ErrDeadlineExceeded) {
			return 0, os.ErrDeadlineExceeded
		}
		return 0, err
	}
	return len(p), nil
}

func (c *packetConnCF) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()

	_ = c.tc.writeFrame(Frame{Type: TypeClose, ConnID: c.s.id, Nonce: c.tc.nonceGen.Next()})
	c.tc.removeUDPSession(c.s.id, net.ErrClosed)
	return nil
}

func (c *packetConnCF) LocalAddr() net.Addr { return dummyAddr("cf-local") }

func (c *packetConnCF) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

func (c *packetConnCF) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return nil
}

func (c *packetConnCF) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}
