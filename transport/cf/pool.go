package cf

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
)

type Pool struct {
	clients []*Client
	next    atomic.Uint32
}

func NewPool(opt Option) (*Pool, error) {
	if opt.TunnelCount < 1 {
		opt.TunnelCount = 1
	}
	clients := make([]*Client, 0, opt.TunnelCount)
	for i := 0; i < opt.TunnelCount; i++ {
		c, err := NewClient(opt)
		if err != nil {
			for _, client := range clients {
				_ = client.Close()
			}
			return nil, err
		}
		clients = append(clients, c)
	}
	return newPoolFromClients(clients), nil
}

func newPoolFromClients(clients []*Client) *Pool {
	return &Pool{clients: clients}
}

func (p *Pool) nextClient() *Client {
	if len(p.clients) == 0 {
		return nil
	}
	idx := int(p.next.Add(1)-1) % len(p.clients)
	return p.clients[idx]
}

func (p *Pool) OpenStream(ctx context.Context, target string) (net.Conn, error) {
	c := p.nextClient()
	if c == nil {
		return nil, errors.New("no tunnel available")
	}
	return c.OpenStream(ctx, target)
}

func (p *Pool) OpenPacket(ctx context.Context, target string) (net.PacketConn, error) {
	c := p.nextClient()
	if c == nil {
		return nil, errors.New("no tunnel available")
	}
	return c.OpenPacket(ctx, target)
}

func (p *Pool) Close() error {
	var first error
	for _, c := range p.clients {
		if err := c.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
