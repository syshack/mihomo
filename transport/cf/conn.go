package cf

import (
	"io"
	"net"
	"sync"
	"time"
)

type streamConn struct {
	tc *Client
	s  *session

	mu      sync.Mutex
	readBuf []byte
	closed  bool
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
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()

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
	}
}

func (c *streamConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	c.mu.Unlock()

	payload := make([]byte, len(p))
	copy(payload, p)
	if err := c.tc.writeFrame(Frame{Type: TypeData, ConnID: c.s.id, Nonce: c.tc.nonceGen.Next(), Payload: payload}); err != nil {
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
	_ = t
	return nil
}
func (c *streamConn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *streamConn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }

type dummyAddr string

func (d dummyAddr) Network() string { return "cf" }
func (d dummyAddr) String() string  { return string(d) }
