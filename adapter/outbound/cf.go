package outbound

import (
	"context"
	"net"
	"strconv"
	"time"

	C "github.com/metacubex/mihomo/constant"
	cftransport "github.com/metacubex/mihomo/transport/cf"
)

type CF struct {
	*Base
	option *CFOption
	client *cftransport.Client
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
	ReconnectInitialBackoff int    `proxy:"reconnect_initial_backoff_ms,omitempty"`
	ReconnectMaxBackoff     int    `proxy:"reconnect_max_backoff_ms,omitempty"`
	FlushIntervalMs         int    `proxy:"flush_interval_ms,omitempty"`
	ReadBufSize             int    `proxy:"read_buf_size,omitempty"`
	FlushBatchBytes         int    `proxy:"flush_batch_bytes,omitempty"`
}

func (c *CF) DialContext(ctx context.Context, metadata *C.Metadata) (_ C.Conn, err error) {
	stream, err := c.client.OpenStream(ctx, metadata.RemoteAddress())
	if err != nil {
		return nil, err
	}
	return NewConn(stream, c), nil
}

func (c *CF) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	return nil, C.ErrNotSupport
}

func (c *CF) ProxyInfo() C.ProxyInfo {
	info := c.Base.ProxyInfo()
	info.DialerProxy = c.option.DialerProxy
	return info
}

func (c *CF) Close() error {
	if c.client != nil {
		return c.client.Close()
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
			UDP:          false,
			TFO:          option.TFO,
			MPTCP:        option.MPTCP,
			Interface:    option.Interface,
			RoutingMark:  option.RoutingMark,
			Prefer:       option.IPVersion,
		}),
		option: &option,
	}
	outbound.dialer = option.NewDialer(outbound.DialOptions())

	client, err := cftransport.NewClient(cftransport.Option{
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
	})
	if err != nil {
		return nil, err
	}
	outbound.client = client
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
