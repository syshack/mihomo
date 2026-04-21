package cf

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Option struct {
	ServerAddr string
	Secret     string

	OpenTimeout             time.Duration
	IdleTimeout             time.Duration
	WriteTimeout            time.Duration
	ReconnectInitialBackoff time.Duration
	ReconnectMaxBackoff     time.Duration
	FlushInterval           time.Duration
	ReadBufSize             int
	FlushBatch              int
}

type session struct {
	id     uint32
	target string

	opened chan openResult
	readCh chan []byte
	done   chan struct{}
	once   sync.Once
}

func (s *session) closeDone() {
	s.once.Do(func() { close(s.done) })
}

type openResult struct {
	rep byte
	err error
}

type writeReq struct {
	f   Frame
	res chan error
}

type Client struct {
	opt Option

	secret []byte

	conn      net.Conn
	reader    *bufio.Reader
	writer    *bufio.Writer
	connected atomic.Bool
	connMu    sync.RWMutex

	nonceGen *nonceGen
	nonceWin *NonceWindow

	writeQ chan writeReq

	reconnMu sync.Mutex

	nextConnID atomic.Uint32

	sessionsMu sync.Mutex
	sessions   map[uint32]*session

	closed    chan struct{}
	closeOnce sync.Once
}

func NewClient(opt Option) (*Client, error) {
	conn, err := net.DialTimeout("tcp", opt.ServerAddr, opt.OpenTimeout)
	if err != nil {
		return nil, err
	}
	if err := writeClientHello(conn, []byte(opt.Secret)); err != nil {
		_ = conn.Close()
		return nil, err
	}

	tc := &Client{
		opt:      opt,
		secret:   []byte(opt.Secret),
		conn:     conn,
		reader:   bufio.NewReader(conn),
		writer:   bufio.NewWriterSize(conn, 64*1024),
		nonceGen: newNonceGen(),
		nonceWin: NewNonceWindow(),
		writeQ:   make(chan writeReq, 2048),
		sessions: make(map[uint32]*session),
		closed:   make(chan struct{}),
	}
	tc.connected.Store(true)
	tc.nextConnID.Store(1)

	go tc.writerLoop()
	go tc.readLoop(conn, tc.reader)
	go tc.heartbeatLoop()

	return tc, nil
}

func (tc *Client) OpenStream(ctx context.Context, target string) (net.Conn, error) {
	addrPayload, err := EncodeAddress(target)
	if err != nil {
		return nil, err
	}

	id := tc.allocConnID()
	s := &session{id: id, target: target, opened: make(chan openResult, 1), readCh: make(chan []byte, 128), done: make(chan struct{})}
	tc.addSession(id, s)

	if err := tc.writeFrame(Frame{Type: TypeOpen, ConnID: id, Nonce: tc.nonceGen.Next(), Payload: addrPayload}); err != nil {
		tc.removeSession(id)
		return nil, err
	}

	timer := time.NewTimer(tc.opt.OpenTimeout)
	defer timer.Stop()

	select {
	case r := <-s.opened:
		if r.err != nil {
			tc.removeSession(id)
			return nil, r.err
		}
		if r.rep != 0x00 {
			tc.removeSession(id)
			return nil, fmt.Errorf("remote open failed rep=%d", r.rep)
		}
		return newStreamConn(tc, s), nil
	case <-timer.C:
		tc.removeSession(id)
		return nil, errors.New("open timeout")
	case <-ctx.Done():
		tc.removeSession(id)
		return nil, ctx.Err()
	case <-tc.closed:
		tc.removeSession(id)
		return nil, errors.New("tunnel closed")
	}
}

func (tc *Client) Close() error {
	tc.closeWithErr(nil)
	return nil
}

func (tc *Client) allocConnID() uint32 {
	for {
		id := tc.nextConnID.Add(1)
		if id != 0 {
			return id
		}
	}
}

func (tc *Client) addSession(id uint32, s *session) {
	tc.sessionsMu.Lock()
	tc.sessions[id] = s
	tc.sessionsMu.Unlock()
}

func (tc *Client) getSession(id uint32) *session {
	tc.sessionsMu.Lock()
	s := tc.sessions[id]
	tc.sessionsMu.Unlock()
	return s
}

func (tc *Client) removeSession(id uint32) {
	tc.sessionsMu.Lock()
	s := tc.sessions[id]
	if s != nil {
		delete(tc.sessions, id)
	}
	tc.sessionsMu.Unlock()
	tc.nonceWin.Remove(id)
	if s != nil {
		s.closeDone()
	}
}

func (tc *Client) closeAllSessions() {
	tc.sessionsMu.Lock()
	ids := make([]uint32, 0, len(tc.sessions))
	for id := range tc.sessions {
		ids = append(ids, id)
	}
	tc.sessionsMu.Unlock()
	for _, id := range ids {
		tc.removeSession(id)
	}
}

func (tc *Client) closeWithErr(_ error) {
	tc.closeOnce.Do(func() {
		close(tc.closed)
		tc.connected.Store(false)
		tc.connMu.Lock()
		c := tc.conn
		tc.conn = nil
		tc.reader = nil
		tc.writer = nil
		tc.connMu.Unlock()
		if c != nil {
			_ = c.Close()
		}
		tc.closeAllSessions()
	})
}

func (tc *Client) writeFrame(f Frame) error {
	req := writeReq{f: f, res: make(chan error, 1)}
	select {
	case <-tc.closed:
		return errors.New("tunnel closed")
	default:
	}
	select {
	case tc.writeQ <- req:
	case <-tc.closed:
		return errors.New("tunnel closed")
	default:
		return errors.New("writer queue full")
	}
	select {
	case err := <-req.res:
		return err
	case <-tc.closed:
		return errors.New("tunnel closed")
	}
}

func (tc *Client) writerLoop() {
	ticker := time.NewTicker(tc.opt.FlushInterval)
	defer ticker.Stop()
	flush := func(conn net.Conn, writer *bufio.Writer) error {
		if writer == nil || writer.Buffered() == 0 {
			return nil
		}
		_ = conn.SetWriteDeadline(time.Now().Add(tc.opt.WriteTimeout))
		return writer.Flush()
	}
	for {
		select {
		case <-tc.closed:
			return
		case req := <-tc.writeQ:
			tc.connMu.RLock()
			conn := tc.conn
			writer := tc.writer
			connected := tc.connected.Load()
			tc.connMu.RUnlock()
			if !connected || conn == nil || writer == nil {
				req.res <- errors.New("tunnel unavailable")
				continue
			}

			b, err := marshalFrame(req.f, tc.secret)
			if err == nil {
				_ = conn.SetWriteDeadline(time.Now().Add(tc.opt.WriteTimeout))
				_, err = writer.Write(b)
			}
			if err == nil && req.f.Type != TypeData {
				err = flush(conn, writer)
			}
			if err == nil && writer.Buffered() >= tc.opt.FlushBatch {
				err = flush(conn, writer)
			}
			if err != nil {
				go tc.handleDisconnect(conn, err)
			}
			req.res <- err
		case <-ticker.C:
			tc.connMu.RLock()
			conn := tc.conn
			writer := tc.writer
			connected := tc.connected.Load()
			tc.connMu.RUnlock()
			if !connected || conn == nil || writer == nil {
				continue
			}
			if err := flush(conn, writer); err != nil {
				go tc.handleDisconnect(conn, err)
			}
		}
	}
}

func (tc *Client) readLoop(conn net.Conn, reader *bufio.Reader) {
	for {
		_ = conn.SetReadDeadline(time.Now().Add(tc.opt.IdleTimeout))
		f, err := readFrame(reader, tc.secret)
		if err != nil {
			tc.handleDisconnect(conn, err)
			return
		}
		if !tc.nonceWin.Accept(f.ConnID, f.Nonce) {
			continue
		}
		tc.dispatchFrame(f)
	}
}

func (tc *Client) dispatchFrame(f Frame) {
	s := tc.getSession(f.ConnID)
	if s == nil {
		if f.Type == TypePing {
			_ = tc.writeFrame(Frame{Type: TypePong, ConnID: f.ConnID, Nonce: tc.nonceGen.Next()})
			return
		}
		if f.Type == TypePong || f.Type == TypeClose {
			return
		}
		_ = tc.writeFrame(Frame{Type: TypeClose, ConnID: f.ConnID, Nonce: tc.nonceGen.Next()})
		return
	}

	switch f.Type {
	case TypeOpenOK:
		select {
		case s.opened <- openResult{rep: 0x00}:
		default:
		}
	case TypeOpenErr:
		rep := byte(0x01)
		if len(f.Payload) > 0 {
			rep = f.Payload[0]
		}
		select {
		case s.opened <- openResult{rep: rep, err: fmt.Errorf("open error rep=%d", rep)}:
		default:
		}
		tc.removeSession(f.ConnID)
	case TypeData:
		select {
		case s.readCh <- f.Payload:
		default:
			tc.removeSession(f.ConnID)
			_ = tc.writeFrame(Frame{Type: TypeClose, ConnID: f.ConnID, Nonce: tc.nonceGen.Next()})
		}
	case TypeClose:
		tc.removeSession(f.ConnID)
	case TypePing:
		_ = tc.writeFrame(Frame{Type: TypePong, ConnID: f.ConnID, Nonce: tc.nonceGen.Next()})
	case TypePong:
	}
}

func (tc *Client) handleDisconnect(deadConn net.Conn, _ error) {
	tc.reconnMu.Lock()
	defer tc.reconnMu.Unlock()

	select {
	case <-tc.closed:
		return
	default:
	}

	tc.connMu.Lock()
	if tc.conn != deadConn {
		tc.connMu.Unlock()
		return
	}
	tc.connected.Store(false)
	c := tc.conn
	tc.conn = nil
	tc.reader = nil
	tc.writer = nil
	tc.connMu.Unlock()
	if c != nil {
		_ = c.Close()
	}

	tc.closeAllSessions()

	backoff := tc.opt.ReconnectInitialBackoff
	for {
		select {
		case <-tc.closed:
			return
		default:
		}

		conn, err := net.DialTimeout("tcp", tc.opt.ServerAddr, tc.opt.OpenTimeout)
		if err == nil {
			if err = writeClientHello(conn, tc.secret); err == nil {
				reader := bufio.NewReader(conn)
				writer := bufio.NewWriterSize(conn, 64*1024)
				tc.connMu.Lock()
				tc.conn = conn
				tc.reader = reader
				tc.writer = writer
				tc.connected.Store(true)
				tc.connMu.Unlock()
				go tc.readLoop(conn, reader)
				return
			}
			_ = conn.Close()
		}

		time.Sleep(jitterDuration(backoff))
		if backoff < tc.opt.ReconnectMaxBackoff {
			backoff *= 2
			if backoff > tc.opt.ReconnectMaxBackoff {
				backoff = tc.opt.ReconnectMaxBackoff
			}
		}
	}
}

func (tc *Client) heartbeatLoop() {
	interval := tc.opt.IdleTimeout / 3
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	if interval > 30*time.Second {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-tc.closed:
			return
		case <-ticker.C:
			if !tc.connected.Load() {
				continue
			}
			if err := tc.writeFrame(Frame{Type: TypePing, ConnID: 0, Nonce: tc.nonceGen.Next()}); err != nil {
				tc.connMu.RLock()
				c := tc.conn
				tc.connMu.RUnlock()
				if c != nil {
					tc.handleDisconnect(c, err)
				}
			}
		}
	}
}

type nonceGen struct{ v atomic.Uint32 }

func newNonceGen() *nonceGen {
	var seed [4]byte
	if _, err := rand.Read(seed[:]); err != nil {
		binary.BigEndian.PutUint32(seed[:], uint32(time.Now().UnixNano()))
	}
	n := &nonceGen{}
	n.v.Store(binary.BigEndian.Uint32(seed[:]))
	return n
}

func (n *nonceGen) Next() uint32 { return n.v.Add(1) }

func jitterDuration(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	delta := base / 5
	if delta < time.Millisecond {
		return base
	}
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return base
	}
	rangeSize := int64(2*delta + 1)
	offset := time.Duration(int64(binary.BigEndian.Uint16(b[:]))%rangeSize) - delta
	return base + offset
}
