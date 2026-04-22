package outbound

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	cftransport "github.com/metacubex/mihomo/transport/cf"
)

type cfMuxPacketConn struct {
	client *cftransport.Client

	mu            sync.RWMutex
	conns         map[string]net.PacketConn
	readDeadline  time.Time
	writeDeadline time.Time

	readQ chan cfMuxPacket

	closed    chan struct{}
	closeOnce sync.Once
}

type cfMuxPacket struct {
	b    []byte
	addr net.Addr
	err  error
}

func newCFMuxPacketConn(client *cftransport.Client) net.PacketConn {
	return &cfMuxPacketConn{
		client: client,
		conns:  make(map[string]net.PacketConn),
		readQ:  make(chan cfMuxPacket, 512),
		closed: make(chan struct{}),
	}
}

func (c *cfMuxPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	deadline := c.getReadDeadline()

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
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case <-timeout:
		return 0, nil, os.ErrDeadlineExceeded
	case pkt := <-c.readQ:
		if pkt.err != nil {
			return 0, nil, pkt.err
		}
		n := copy(p, pkt.b)
		return n, pkt.addr, nil
	}
}

func (c *cfMuxPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if addr == nil {
		return 0, errors.New("nil addr")
	}

	deadline := c.getWriteDeadline()
	pc, err := c.getOrCreateConn(addr, deadline)
	if err != nil {
		return 0, err
	}

	if !deadline.IsZero() {
		_ = pc.SetWriteDeadline(deadline)
	}

	return pc.WriteTo(b, addr)
}

func (c *cfMuxPacketConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)

		c.mu.Lock()
		for key, pc := range c.conns {
			_ = pc.Close()
			delete(c.conns, key)
		}
		c.mu.Unlock()
	})

	return nil
}

func (c *cfMuxPacketConn) LocalAddr() net.Addr {
	return cfMuxAddr("cf-mux")
}

func (c *cfMuxPacketConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

func (c *cfMuxPacketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return nil
}

func (c *cfMuxPacketConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

func (c *cfMuxPacketConn) getReadDeadline() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.readDeadline
}

func (c *cfMuxPacketConn) getWriteDeadline() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.writeDeadline
}

func (c *cfMuxPacketConn) getOrCreateConn(addr net.Addr, deadline time.Time) (net.PacketConn, error) {
	select {
	case <-c.closed:
		return nil, net.ErrClosed
	default:
	}

	key := addr.String()

	c.mu.RLock()
	if pc := c.conns[key]; pc != nil {
		c.mu.RUnlock()
		return pc, nil
	}
	c.mu.RUnlock()

	ctx := context.Background()
	var cancel context.CancelFunc
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return nil, os.ErrDeadlineExceeded
		}
		ctx, cancel = context.WithTimeout(context.Background(), d)
	}
	if cancel != nil {
		defer cancel()
	}

	pc, err := c.client.OpenPacket(ctx, key)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	if old := c.conns[key]; old != nil {
		c.mu.Unlock()
		_ = pc.Close()
		return old, nil
	}
	c.conns[key] = pc
	c.mu.Unlock()

	go c.readLoop(key, pc)

	return pc, nil
}

func (c *cfMuxPacketConn) readLoop(key string, pc net.PacketConn) {
	buf := make([]byte, 64*1024)

	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				select {
				case c.readQ <- cfMuxPacket{err: err}:
				case <-c.closed:
				}
			}
			c.mu.Lock()
			if cur := c.conns[key]; cur == pc {
				delete(c.conns, key)
			}
			c.mu.Unlock()
			return
		}

		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		select {
		case c.readQ <- cfMuxPacket{b: pkt, addr: addr}:
		case <-c.closed:
			return
		}
	}
}

type cfMuxAddr string

func (a cfMuxAddr) Network() string { return "cf" }
func (a cfMuxAddr) String() string  { return string(a) }
