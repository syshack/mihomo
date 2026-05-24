package outbound

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	C "github.com/metacubex/mihomo/constant"
	cftransport "github.com/metacubex/mihomo/transport/cf"
)

type CF struct {
	*Base
	option   *CFOption
	pool     *cftransport.Pool
	clientMu sync.Mutex
	cfOpt    cftransport.Option
}

func (c *CF) getClient() (*cftransport.Pool, error) {
	c.clientMu.Lock()
	defer c.clientMu.Unlock()

	if c.pool != nil {
		return c.pool, nil
	}

	pool, err := cftransport.NewPool(c.cfOpt)
	if err != nil {
		return nil, err
	}

	c.pool = pool
	return c.pool, nil
}

type CFOption struct {
	BasicOption
	Name                    string `proxy:"name"`
	Server                  string `proxy:"server"`
	Port                    int    `proxy:"port"`
	Secret                  string `proxy:"secret"`
	OpenTimeoutMs           int    `proxy:"open_timeout_ms,omitempty"`
	IdleTimeoutMs           int    `proxy:"idle_timeout_ms,omitempty"`
	WriteTimeoutMs          int    `proxy:"write_timeout_ms,omitempty"`
	OpenDirect              bool   `proxy:"open_direct,omitempty"`
	ReconnectInitialBackoff int    `proxy:"reconnect_initial_backoff_ms,omitempty"`
	ReconnectMaxBackoff     int    `proxy:"reconnect_max_backoff_ms,omitempty"`
	FlushIntervalMs         int    `proxy:"flush_interval_ms,omitempty"`
	ReadBufSize             int    `proxy:"read_buf_size,omitempty"`
	FlushBatchBytes         int    `proxy:"flush_batch_bytes,omitempty"`
	TunnelCount             int    `proxy:"tunnel_count,omitempty"`
	ObfsNegotiate           bool   `proxy:"obfs_negotiate,omitempty"`
	ObfsStrictNegotiate     bool   `proxy:"obfs_strict_negotiate,omitempty"`
	ObfsFallbackMode        string `proxy:"obfs_fallback_mode,omitempty"`
	ObfsPadMin              int    `proxy:"obfs_pad_min,omitempty"`
	ObfsPadMax              int    `proxy:"obfs_pad_max,omitempty"`
	ObfsRotateMin           int    `proxy:"obfs_rotate_min,omitempty"`
	ObfsRotateMax           int    `proxy:"obfs_rotate_max,omitempty"`
	ObfsDynamicRotate       bool   `proxy:"obfs_dynamic_rotate,omitempty"`
	ObfsRotateSpan          int    `proxy:"obfs_rotate_span,omitempty"`
	ObfsJitterMinMs         int    `proxy:"obfs_jitter_min_ms,omitempty"`
	ObfsJitterMaxMs         int    `proxy:"obfs_jitter_max_ms,omitempty"`
}

func (c *CF) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	client, err := c.getClient()
	if err != nil {
		return nil, err
	}

	stream, err := client.OpenStream(ctx, metadata.RemoteAddress())
	if err != nil {
		return nil, err
	}
	return NewConn(stream, c), nil
}

func (c *CF) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if err := c.ResolveUDP(ctx, metadata); err != nil {
		return nil, err
	}

	client, err := c.getClient()
	if err != nil {
		return nil, err
	}

	pc := newCFMuxPacketConn(client)

	return newPacketConn(N.NewThreadSafePacketConn(pc), c), nil
}

func (c *CF) ProxyInfo() C.ProxyInfo {
	info := c.Base.ProxyInfo()
	info.DialerProxy = c.option.DialerProxy
	return info
}

func (c *CF) SupportUOT() bool {
	return true
}

func (c *CF) Close() error {
	c.clientMu.Lock()
	pool := c.pool
	c.pool = nil
	c.clientMu.Unlock()

	if pool != nil {
		return pool.Close()
	}
	return nil
}

func NewCF(option CFOption) (*CF, error) {
	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	outbound := &CF{
		Base: NewBase(BaseOption{
			Name:         option.Name,
			Addr:         addr,
			Type:         C.CF,
			ProviderName: option.ProviderName,
			UDP:          true,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())
	if option.OpenDirect {
		outbound.dialer = nil
	}

	outbound.cfOpt = cftransport.Option{
		ServerAddr:              addr,
		Secret:                  option.Secret,
		Dialer:                  outbound.dialer,
		OpenTimeout:             msOrDefault(option.OpenTimeoutMs, 20*time.Second),
		IdleTimeout:             msOrDefault(option.IdleTimeoutMs, 300*time.Second),
		WriteTimeout:            msOrDefault(option.WriteTimeoutMs, 15*time.Second),
		ReconnectInitialBackoff: msOrDefault(option.ReconnectInitialBackoff, 500*time.Millisecond),
		ReconnectMaxBackoff:     msOrDefault(option.ReconnectMaxBackoff, 8*time.Second),
		FlushInterval:           msOrDefault(option.FlushIntervalMs, 3*time.Millisecond),
		ReadBufSize:             intOrDefault(option.ReadBufSize, 64*1024),
		FlushBatch:              intOrDefault(option.FlushBatchBytes, 64*1024),
		TunnelCount:             intOrDefault(option.TunnelCount, 1),
		ObfsNegotiate:           option.ObfsNegotiate,
		ObfsStrictNegotiate:     option.ObfsStrictNegotiate,
		ObfsFallbackMode:        option.ObfsFallbackMode,
		ObfsPadMin:              option.ObfsPadMin,
		ObfsPadMax:              option.ObfsPadMax,
		ObfsRotateMin:           option.ObfsRotateMin,
		ObfsRotateMax:           option.ObfsRotateMax,
		ObfsDynamicRotate:       option.ObfsDynamicRotate,
		ObfsRotateSpan:          option.ObfsRotateSpan,
		ObfsJitterMinMs:         option.ObfsJitterMinMs,
		ObfsJitterMaxMs:         option.ObfsJitterMaxMs,
	}

	return outbound, nil
}

func msOrDefault(ms int, d time.Duration) time.Duration {
	if ms <= 0 {
		return d
	}
	return time.Duration(ms) * time.Millisecond
}

func intOrDefault(v, d int) int {
	if v <= 0 {
		return d
	}
	return v
}
