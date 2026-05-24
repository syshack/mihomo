package cf

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/log"
)

type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type Option struct {
	ServerAddr string
	Secret     string
	Dialer     ContextDialer

	OpenTimeout             time.Duration
	IdleTimeout             time.Duration
	WriteTimeout            time.Duration
	ReconnectInitialBackoff time.Duration
	ReconnectMaxBackoff     time.Duration
	FlushInterval           time.Duration
	ReadBufSize             int
	FlushBatch              int
	TunnelCount             int

	ObfsNegotiate       bool
	ObfsStrictNegotiate bool
	ObfsFallbackMode    string
	ObfsPadMin          int
	ObfsPadMax          int
	ObfsRotateMin       int
	ObfsRotateMax       int
	ObfsDynamicRotate   bool
	ObfsRotateSpan      int
	ObfsJitterMinMs     int
	ObfsJitterMaxMs     int
}

func (o Option) dialTCP(timeout time.Duration) (net.Conn, error) {
	if o.Dialer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return o.Dialer.DialContext(ctx, "tcp", o.ServerAddr)
	}
	return net.DialTimeout("tcp", o.ServerAddr, timeout)
}

type session struct {
	id     uint32
	target string

	opened chan openResult
	readCh chan []byte
	done   chan struct{}
	once   sync.Once

	errMu sync.RWMutex
	err   error
}

func (s *session) closeDone() {
	s.once.Do(func() { close(s.done) })
}

func (s *session) setErr(err error) {
	s.errMu.Lock()
	s.err = err
	s.errMu.Unlock()
}

func (s *session) getErr() error {
	s.errMu.RLock()
	err := s.err
	s.errMu.RUnlock()
	if err == nil {
		return io.EOF
	}
	return err
}

type udpPacket struct {
	b []byte
}

type udpSession struct {
	id     uint32
	target string

	opened chan openResult
	readCh chan udpPacket
	done   chan struct{}
	once   sync.Once

	errMu sync.RWMutex
	err   error
}

func (s *udpSession) closeDone() {
	s.once.Do(func() { close(s.done) })
}

func (s *udpSession) setErr(err error) {
	s.errMu.Lock()
	s.err = err
	s.errMu.Unlock()
}

func (s *udpSession) getErr() error {
	s.errMu.RLock()
	err := s.err
	s.errMu.RUnlock()
	if err == nil {
		return io.EOF
	}
	return err
}

type openResult struct {
	rep byte
	err error
}

type writeReq struct {
	f       Frame
	res     chan error
	recycle func()
}

type Client struct {
	opt Option

	secret []byte
	obfs   ObfsParams
	hello  HelloOptions

	conn      net.Conn
	reader    *bufio.Reader
	writer    *bufio.Writer
	connected atomic.Bool
	connMu    sync.RWMutex

	nonceGen *nonceGen
	nonceWin *NonceWindow

	writeQ chan writeReq
	ctrlQ  chan writeReq

	reconnMu sync.Mutex

	nextConnID atomic.Uint32

	sessionsMu sync.RWMutex
	sessions   map[uint32]*session
	udpSession map[uint32]*udpSession

	closed    chan struct{}
	closeOnce sync.Once

	connGen atomic.Uint64
}

const (
	sessionReadQueueSize = 256
	dataEnqueueTimeout   = 300 * time.Millisecond
	udpEnqueueTimeout    = 300 * time.Millisecond
)

func NewClient(opt Option) (*Client, error) {
	initialObfs := ObfsParams{
		PadMin:        uint8(opt.ObfsPadMin),
		PadMax:        uint8(opt.ObfsPadMax),
		RotateMin:     uint8(opt.ObfsRotateMin),
		RotateMax:     uint8(opt.ObfsRotateMax),
		DynamicRotate: opt.ObfsDynamicRotate,
		RotateSpan:    uint8(opt.ObfsRotateSpan),
		JitterMinMs:   uint8(opt.ObfsJitterMinMs),
		JitterMaxMs:   uint8(opt.ObfsJitterMaxMs),
	}
	if !opt.ObfsNegotiate && opt.ObfsPadMax == 0 && opt.ObfsRotateMin == 0 && opt.ObfsRotateMax == 0 && opt.ObfsRotateSpan == 0 {
		initialObfs = defaultObfsParams()
	}
	normalizedObfs, err := initialObfs.Normalize()
	if err != nil {
		return nil, err
	}

	conn, err := opt.dialTCP(opt.OpenTimeout)
	if err != nil {
		return nil, err
	}
	helloOpts := HelloOptions{Negotiate: opt.ObfsNegotiate, Params: normalizedObfs}
	negotiatedObfs, err := writeClientHelloWithOptions(conn, []byte(opt.Secret), helloOpts)
	if err != nil {
		if helloOpts.Negotiate {
			if opt.ObfsStrictNegotiate || strings.EqualFold(opt.ObfsFallbackMode, "fail") {
				_ = conn.Close()
				return nil, err
			}
			log.Warnln("[CF] obfs negotiate failed, fallback to legacy hello: %v", err)
			_ = conn.Close()
			conn, err = opt.dialTCP(opt.OpenTimeout)
			if err != nil {
				return nil, err
			}
			if err = writeClientHello(conn, []byte(opt.Secret)); err != nil {
				_ = conn.Close()
				return nil, err
			}
			negotiatedObfs = defaultObfsParams()
		} else {
			_ = conn.Close()
			return nil, err
		}
	} else if helloOpts.Negotiate {
		log.Debugln("[CF] obfs negotiated pad=%d rotate=%d-%d dynamic=%t span=%d", negotiatedObfs.PadMax, negotiatedObfs.RotateMin, negotiatedObfs.RotateMax, negotiatedObfs.DynamicRotate, negotiatedObfs.RotateSpan)
	}

	tc := &Client{
		opt:        opt,
		secret:     []byte(opt.Secret),
		obfs:       negotiatedObfs,
		hello:      helloOpts,
		conn:       conn,
		reader:     bufio.NewReader(conn),
		writer:     bufio.NewWriterSize(conn, 64*1024),
		nonceGen:   newNonceGen(),
		nonceWin:   NewNonceWindow(),
		writeQ:     make(chan writeReq, 2048),
		ctrlQ:      make(chan writeReq, 512),
		sessions:   make(map[uint32]*session),
		udpSession: make(map[uint32]*udpSession),
		closed:     make(chan struct{}),
	}
	tc.connected.Store(true)
	tc.nextConnID.Store(1)
	tc.connGen.Store(1)

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

	gen := tc.connGen.Load()
	id := tc.allocConnID()
	s := &session{id: id, target: target, opened: make(chan openResult, 1), readCh: make(chan []byte, sessionReadQueueSize), done: make(chan struct{})}
	tc.addSession(id, s)
	log.Debugln("[CF] open start conn=%d target=%s", id, target)

	if err := tc.writeFrame(Frame{Type: TypeOpen, ConnID: id, Nonce: tc.nonceGen.Next(), Payload: addrPayload}); err != nil {
		tc.removeSession(id, err)
		return nil, err
	}

	openWait := tc.opt.OpenTimeout
	if dl, ok := ctx.Deadline(); ok {
		remain := time.Until(dl)
		if remain <= 0 {
			tc.removeSession(id, context.DeadlineExceeded)
			return nil, context.DeadlineExceeded
		}
		if openWait <= 0 || remain < openWait {
			openWait = remain
		}
	}
	if openWait <= 0 {
		openWait = 20 * time.Second
	}
	timer := time.NewTimer(openWait)
	defer timer.Stop()

	select {
	case r := <-s.opened:
		if gen != tc.connGen.Load() {
			err := errors.New("tunnel reconnected")
			tc.removeSession(id, err)
			return nil, err
		}
		if r.err != nil {
			tc.removeSession(id, r.err)
			return nil, r.err
		}
		if r.rep != 0x00 {
			err := fmt.Errorf("remote open failed rep=%d", r.rep)
			tc.removeSession(id, err)
			return nil, fmt.Errorf("remote open failed rep=%d", r.rep)
		}
		log.Debugln("[CF] open ok conn=%d target=%s", id, target)
		return newStreamConn(tc, s), nil
	case <-timer.C:
		err := errors.New("open timeout")
		tc.removeSession(id, err)
		return nil, err
	case <-ctx.Done():
		tc.removeSession(id, ctx.Err())
		return nil, ctx.Err()
	case <-s.done:
		return nil, s.getErr()
	case <-tc.closed:
		tc.removeSession(id, errors.New("tunnel closed"))
		return nil, errors.New("tunnel closed")
	}
}

func (tc *Client) OpenPacket(ctx context.Context, target string) (net.PacketConn, error) {
	addrPayload, err := EncodeAddress(target)
	if err != nil {
		return nil, err
	}

	gen := tc.connGen.Load()
	id := tc.allocConnID()
	s := &udpSession{id: id, target: target, opened: make(chan openResult, 1), readCh: make(chan udpPacket, sessionReadQueueSize), done: make(chan struct{})}
	tc.addUDPSession(id, s)
	log.Debugln("[CF] udp open start conn=%d target=%s", id, target)

	if err := tc.writeFrame(Frame{Type: TypeUDPOpen, ConnID: id, Nonce: tc.nonceGen.Next(), Payload: addrPayload}); err != nil {
		tc.removeUDPSession(id, err)
		return nil, err
	}

	openWait := tc.opt.OpenTimeout
	if dl, ok := ctx.Deadline(); ok {
		remain := time.Until(dl)
		if remain <= 0 {
			tc.removeUDPSession(id, context.DeadlineExceeded)
			return nil, context.DeadlineExceeded
		}
		if openWait <= 0 || remain < openWait {
			openWait = remain
		}
	}
	if openWait <= 0 {
		openWait = 20 * time.Second
	}
	timer := time.NewTimer(openWait)
	defer timer.Stop()

	select {
	case r := <-s.opened:
		if gen != tc.connGen.Load() {
			err := errors.New("tunnel reconnected")
			tc.removeUDPSession(id, err)
			return nil, err
		}
		if r.err != nil {
			tc.removeUDPSession(id, r.err)
			return nil, r.err
		}
		if r.rep != 0x00 {
			err := fmt.Errorf("remote udp open failed rep=%d", r.rep)
			tc.removeUDPSession(id, err)
			return nil, err
		}
		log.Debugln("[CF] udp open ok conn=%d target=%s", id, target)
		return newPacketConnCF(tc, s), nil
	case <-timer.C:
		err := errors.New("udp open timeout")
		tc.removeUDPSession(id, err)
		return nil, err
	case <-ctx.Done():
		tc.removeUDPSession(id, ctx.Err())
		return nil, ctx.Err()
	case <-s.done:
		return nil, s.getErr()
	case <-tc.closed:
		tc.removeUDPSession(id, errors.New("tunnel closed"))
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
			if tc.getSession(id) != nil || tc.getUDPSession(id) != nil {
				continue
			}
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
	tc.sessionsMu.RLock()
	s := tc.sessions[id]
	tc.sessionsMu.RUnlock()
	return s
}

func (tc *Client) getObfsParams() ObfsParams {
	tc.connMu.RLock()
	p := tc.obfs
	tc.connMu.RUnlock()
	return p
}

func (tc *Client) addUDPSession(id uint32, s *udpSession) {
	tc.sessionsMu.Lock()
	tc.udpSession[id] = s
	tc.sessionsMu.Unlock()
}

func (tc *Client) getUDPSession(id uint32) *udpSession {
	tc.sessionsMu.RLock()
	s := tc.udpSession[id]
	tc.sessionsMu.RUnlock()
	return s
}

func (tc *Client) removeSession(id uint32, err error) {
	tc.sessionsMu.Lock()
	s := tc.sessions[id]
	if s != nil {
		delete(tc.sessions, id)
	}
	tc.sessionsMu.Unlock()
	tc.nonceWin.Remove(id)
	if s != nil {
		s.setErr(err)
		s.closeDone()
	}
}

func (tc *Client) removeUDPSession(id uint32, err error) {
	tc.sessionsMu.Lock()
	s := tc.udpSession[id]
	if s != nil {
		delete(tc.udpSession, id)
	}
	tc.sessionsMu.Unlock()
	tc.nonceWin.Remove(id)
	if s != nil {
		s.setErr(err)
		s.closeDone()
	}
}

func (tc *Client) closeAllSessions(err error) {
	tc.sessionsMu.Lock()
	ids := make([]uint32, 0, len(tc.sessions)+len(tc.udpSession))
	for id := range tc.sessions {
		ids = append(ids, id)
	}
	for id := range tc.udpSession {
		ids = append(ids, id)
	}
	tc.sessionsMu.Unlock()
	for _, id := range ids {
		tc.removeSession(id, err)
		tc.removeUDPSession(id, err)
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
		tc.closeAllSessions(errors.New("tunnel closed"))
	})
}

func (tc *Client) writeFrame(f Frame) error {
	return tc.writeFrameWithRecycle(f, nil)
}

func (tc *Client) writeFrameWithRecycle(f Frame, recycle func()) error {
	return tc.writeFrameWithTimeout(f, recycle, 0)
}

func (tc *Client) writeFrameWithTimeout(f Frame, recycle func(), timeout time.Duration) error {
	req := writeReq{f: f, res: make(chan error, 1), recycle: recycle}
	enqueueTimeout := tc.opt.WriteTimeout
	if enqueueTimeout <= 0 {
		enqueueTimeout = 5 * time.Second
	}
	if f.Type == TypeData && enqueueTimeout > 2*time.Second {
		enqueueTimeout = 2 * time.Second
	}
	if timeout > 0 && timeout < enqueueTimeout {
		enqueueTimeout = timeout
	}
	timer := time.NewTimer(enqueueTimeout)
	defer timer.Stop()
	select {
	case <-tc.closed:
		if recycle != nil {
			recycle()
		}
		return errors.New("tunnel closed")
	default:
	}
	q := tc.writeQ
	if f.Type != TypeData {
		q = tc.ctrlQ
	}
	select {
	case q <- req:
	case <-tc.closed:
		if recycle != nil {
			recycle()
		}
		return errors.New("tunnel closed")
	case <-timer.C:
		if recycle != nil {
			recycle()
		}
		if timeout > 0 {
			return os.ErrDeadlineExceeded
		}
		return errors.New("writer queue timeout")
	}
	select {
	case err := <-req.res:
		return err
	case <-tc.closed:
		return errors.New("tunnel closed")
	case <-timer.C:
		if timeout > 0 {
			return os.ErrDeadlineExceeded
		}
		return errors.New("write timeout")
	}
}

func (tc *Client) handleWriteReq(req writeReq) {
	tc.handleWriteReqWithScratch(req, nil)
}

func (tc *Client) handleWriteReqWithScratch(req writeReq, scratch []byte) []byte {
	defer func() {
		if req.recycle != nil {
			req.recycle()
		}
	}()
	tc.connMu.RLock()
	conn := tc.conn
	writer := tc.writer
	connected := tc.connected.Load()
	tc.connMu.RUnlock()
	if !connected || conn == nil || writer == nil {
		req.res <- errors.New("tunnel unavailable")
		return scratch
	}
	if req.f.Type == TypeData || req.f.Type == TypeUDPData {
		if d, ok := randomJitter(tc.getObfsParams()); ok {
			time.Sleep(d)
		}
	}

	scratch = scratch[:0]
	b, err := appendFrameWithParams(scratch, req.f, tc.secret, tc.getObfsParams())
	if err == nil {
		scratch = b
		_ = conn.SetWriteDeadline(time.Now().Add(tc.opt.WriteTimeout))
		_, err = writer.Write(b)
	}
	if err == nil && req.f.Type != TypeData {
		err = tc.flushWriter(conn, writer)
	}
	if err == nil && writer.Buffered() >= tc.opt.FlushBatch {
		err = tc.flushWriter(conn, writer)
	}
	if err != nil {
		go tc.handleDisconnect(conn, err)
	}
	req.res <- err
	return scratch
}

func (tc *Client) flushWriter(conn net.Conn, writer *bufio.Writer) error {
	if writer == nil || writer.Buffered() == 0 {
		return nil
	}
	_ = conn.SetWriteDeadline(time.Now().Add(tc.opt.WriteTimeout))
	return writer.Flush()
}

func (tc *Client) writerLoop() {
	ticker := time.NewTicker(tc.opt.FlushInterval)
	defer ticker.Stop()
	scratch := make([]byte, 0, 64*1024)
	for {
		select {
		case <-tc.closed:
			return
		default:
		}

		select {
		case req := <-tc.ctrlQ:
			scratch = tc.handleWriteReqWithScratch(req, scratch)
			continue
		default:
		}

		select {
		case <-tc.closed:
			return
		case req := <-tc.ctrlQ:
			scratch = tc.handleWriteReqWithScratch(req, scratch)
		case req := <-tc.writeQ:
			scratch = tc.handleWriteReqWithScratch(req, scratch)
		case <-ticker.C:
			tc.connMu.RLock()
			conn := tc.conn
			writer := tc.writer
			connected := tc.connected.Load()
			tc.connMu.RUnlock()
			if !connected || conn == nil || writer == nil {
				continue
			}
			if err := tc.flushWriter(conn, writer); err != nil {
				go tc.handleDisconnect(conn, err)
			}
		}
	}
}

func (tc *Client) readLoop(conn net.Conn, reader *bufio.Reader) {
	for {
		_ = conn.SetReadDeadline(time.Now().Add(tc.opt.IdleTimeout))
		f, err := readFrameWithParams(reader, tc.secret, tc.getObfsParams())
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
	us := tc.getUDPSession(f.ConnID)
	if s == nil && us == nil {
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
		if s != nil {
			select {
			case s.opened <- openResult{rep: 0x00}:
			default:
			}
		} else if us != nil {
			select {
			case us.opened <- openResult{rep: 0x00}:
			default:
			}
		}
	case TypeOpenErr:
		rep := byte(0x01)
		if len(f.Payload) > 0 {
			rep = f.Payload[0]
		}
		if s != nil {
			select {
			case s.opened <- openResult{rep: rep, err: fmt.Errorf("open error rep=%d", rep)}:
			default:
			}
			tc.removeSession(f.ConnID, fmt.Errorf("open error rep=%d", rep))
		} else if us != nil {
			select {
			case us.opened <- openResult{rep: rep, err: fmt.Errorf("udp open error rep=%d", rep)}:
			default:
			}
			tc.removeUDPSession(f.ConnID, fmt.Errorf("udp open error rep=%d", rep))
		}
	case TypeData:
		if s == nil {
			return
		}
		timer := time.NewTimer(dataEnqueueTimeout)
		select {
		case s.readCh <- f.Payload:
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
			log.Warnln("[CF] conn=%d read queue congested, closing stream", f.ConnID)
			tc.removeSession(f.ConnID, errors.New("read queue congested"))
			_ = tc.writeFrame(Frame{Type: TypeClose, ConnID: f.ConnID, Nonce: tc.nonceGen.Next()})
			return
		}
	case TypeUDPData:
		if us == nil {
			return
		}
		timer := time.NewTimer(udpEnqueueTimeout)
		select {
		case us.readCh <- udpPacket{b: f.Payload}:
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
			log.Warnln("[CF] udp conn=%d read queue congested, closing stream", f.ConnID)
			tc.removeUDPSession(f.ConnID, errors.New("udp read queue congested"))
			_ = tc.writeFrame(Frame{Type: TypeClose, ConnID: f.ConnID, Nonce: tc.nonceGen.Next()})
			return
		}
	case TypeClose:
		tc.removeSession(f.ConnID, io.EOF)
		tc.removeUDPSession(f.ConnID, io.EOF)
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
	tc.connGen.Add(1)
	discErr := errors.New("tunnel disconnected")
	c := tc.conn
	tc.conn = nil
	tc.reader = nil
	tc.writer = nil
	tc.connMu.Unlock()
	if c != nil {
		_ = c.Close()
	}

	log.Warnln("[CF] tunnel disconnected")
	tc.sessionsMu.Lock()
	for _, s := range tc.sessions {
		s.setErr(discErr)
		s.closeDone()
	}
	for _, us := range tc.udpSession {
		us.setErr(discErr)
		us.closeDone()
	}
	tc.sessionsMu.Unlock()

	backoff := tc.opt.ReconnectInitialBackoff
	for {
		select {
		case <-tc.closed:
			return
		default:
		}

		conn, err := tc.opt.dialTCP(tc.opt.OpenTimeout)
		if err == nil {
			var negotiatedObfs ObfsParams
			negotiatedObfs, err = writeClientHelloWithOptions(conn, tc.secret, tc.hello)
			if err != nil && tc.hello.Negotiate {
				if tc.opt.ObfsStrictNegotiate || strings.EqualFold(tc.opt.ObfsFallbackMode, "fail") {
					_ = conn.Close()
				} else {
					_ = conn.Close()
					conn, err = tc.opt.dialTCP(tc.opt.OpenTimeout)
					if err == nil {
						err = writeClientHello(conn, tc.secret)
						if err == nil {
							negotiatedObfs = defaultObfsParams()
						}
					}
				}
			}
			if err == nil {
				reader := bufio.NewReader(conn)
				writer := bufio.NewWriterSize(conn, 64*1024)
				tc.connMu.Lock()
				tc.conn = conn
				tc.reader = reader
				tc.writer = writer
				tc.obfs = negotiatedObfs
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

func randomJitter(p ObfsParams) (time.Duration, bool) {
	if p.JitterMaxMs == 0 || p.JitterMinMs > p.JitterMaxMs {
		return 0, false
	}
	if p.JitterMinMs == p.JitterMaxMs {
		return time.Duration(p.JitterMinMs) * time.Millisecond, true
	}
	span := int(p.JitterMaxMs-p.JitterMinMs) + 1
	v, err := randByte(span)
	if err != nil {
		return time.Duration(p.JitterMinMs) * time.Millisecond, true
	}
	return time.Duration(int(p.JitterMinMs)+int(v)) * time.Millisecond, true
}
