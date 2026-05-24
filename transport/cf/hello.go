package cf

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	clientHelloMagic = "CFP1"
	clientHelloVer   = byte(1)
	clientHelloLen   = 4 + 1 + 1 + 2 + 16 + 16
	clientHelloVer2  = byte(2)
	clientHelloLen2  = 4 + 1 + 1 + 2 + 16 + 9 + 16

	serverHelloMagic = "CFS1"
	serverHelloVer   = byte(1)
	serverHelloLen   = 4 + 1 + 1 + 2 + 9 + 16
)

type HelloOptions struct {
	Negotiate bool
	Params    ObfsParams
}

type HelloInfo struct {
	Negotiate bool
	Params    ObfsParams
}

func writeClientHello(conn net.Conn, secret []byte) error {
	_, err := writeClientHelloWithOptions(conn, secret, HelloOptions{Negotiate: false})
	return err
}

func writeClientHelloWithOptions(conn net.Conn, secret []byte, opts HelloOptions) (ObfsParams, error) {
	if len(secret) == 0 {
		return ObfsParams{}, fmt.Errorf("empty secret")
	}
	if !opts.Negotiate {
		hello := make([]byte, clientHelloLen)
		copy(hello[0:4], []byte(clientHelloMagic))
		hello[4] = clientHelloVer
		hello[5] = 0
		binary.BigEndian.PutUint16(hello[6:8], 0)
		if _, err := rand.Read(hello[8:24]); err != nil {
			return ObfsParams{}, err
		}
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write(hello[:24])
		sig := mac.Sum(nil)
		copy(hello[24:40], sig[:16])

		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err := conn.Write(hello)
		_ = conn.SetWriteDeadline(time.Time{})
		if err != nil {
			return ObfsParams{}, err
		}
		return defaultObfsParams(), nil
	}

	p, err := opts.Params.Normalize()
	if err != nil {
		return ObfsParams{}, err
	}

	hello := make([]byte, clientHelloLen2)
	copy(hello[0:4], []byte(clientHelloMagic))
	hello[4] = clientHelloVer2
	hello[5] = 1
	binary.BigEndian.PutUint16(hello[6:8], 0)
	if _, err := rand.Read(hello[8:24]); err != nil {
		return ObfsParams{}, err
	}
	encodeObfsParams(hello[24:33], p)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(hello[:33])
	sig := mac.Sum(nil)
	copy(hello[33:49], sig[:16])

	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write(hello)
	_ = conn.SetWriteDeadline(time.Time{})
	if err != nil {
		return ObfsParams{}, err
	}

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer conn.SetReadDeadline(time.Time{})
	buf := make([]byte, serverHelloLen)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return ObfsParams{}, err
	}
	if string(buf[0:4]) != serverHelloMagic {
		return ObfsParams{}, fmt.Errorf("invalid server hello magic")
	}
	if buf[4] != serverHelloVer {
		return ObfsParams{}, fmt.Errorf("unsupported server hello version: %d", buf[4])
	}
	mac = hmac.New(sha256.New, secret)
	_, _ = mac.Write(buf[:17])
	want := mac.Sum(nil)
	if !hmac.Equal(buf[17:33], want[:16]) {
		return ObfsParams{}, fmt.Errorf("invalid server hello signature")
	}
	np, err := decodeObfsParams(buf[8:17])
	if err != nil {
		return ObfsParams{}, err
	}
	return np, nil
}

func consumeClientHelloReader(br *bufio.Reader, secret []byte) (*bufio.Reader, error) {
	r, _, err := consumeClientHelloInfoReader(br, secret)
	return r, err
}

func consumeClientHelloInfoReader(br *bufio.Reader, secret []byte) (*bufio.Reader, HelloInfo, error) {
	if len(secret) == 0 {
		return nil, HelloInfo{}, fmt.Errorf("empty secret")
	}
	prefix := make([]byte, 8)
	if _, err := io.ReadFull(br, prefix); err != nil {
		return nil, HelloInfo{}, err
	}
	if string(prefix[0:4]) != clientHelloMagic {
		return nil, HelloInfo{}, fmt.Errorf("invalid hello magic")
	}
	ver := prefix[4]
	if ver != clientHelloVer && ver != clientHelloVer2 {
		return nil, HelloInfo{}, fmt.Errorf("unsupported hello version: %d", ver)
	}

	if ver == clientHelloVer {
		rest := make([]byte, clientHelloLen-8)
		if _, err := io.ReadFull(br, rest); err != nil {
			return nil, HelloInfo{}, err
		}
		hello := append(prefix, rest...)
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write(hello[:24])
		want := mac.Sum(nil)
		if !hmac.Equal(hello[24:40], want[:16]) {
			return nil, HelloInfo{}, fmt.Errorf("invalid hello signature")
		}
		return br, HelloInfo{Negotiate: false, Params: defaultObfsParams()}, nil
	}

	rest := make([]byte, clientHelloLen2-8)
	if _, err := io.ReadFull(br, rest); err != nil {
		return nil, HelloInfo{}, err
	}
	hello := append(prefix, rest...)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(hello[:33])
	want := mac.Sum(nil)
	if !hmac.Equal(hello[33:49], want[:16]) {
		return nil, HelloInfo{}, fmt.Errorf("invalid hello signature")
	}
	p, err := decodeObfsParams(hello[24:33])
	if err != nil {
		return nil, HelloInfo{}, err
	}
	return br, HelloInfo{Negotiate: hello[5]&1 == 1, Params: p}, nil
}

func writeServerHello(conn net.Conn, secret []byte, params ObfsParams) error {
	p, err := params.Normalize()
	if err != nil {
		return err
	}
	buf := make([]byte, serverHelloLen)
	copy(buf[0:4], []byte(serverHelloMagic))
	buf[4] = serverHelloVer
	buf[5] = 1
	binary.BigEndian.PutUint16(buf[6:8], 0)
	encodeObfsParams(buf[8:17], p)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(buf[:17])
	sig := mac.Sum(nil)
	copy(buf[17:33], sig[:16])

	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write(buf)
	_ = conn.SetWriteDeadline(time.Time{})
	return err
}

func encodeObfsParams(dst []byte, p ObfsParams) {
	if len(dst) < 9 {
		return
	}
	dst[0] = p.PadMax
	dst[1] = p.RotateMin
	dst[2] = p.RotateMax
	if p.DynamicRotate {
		dst[3] = 1
	} else {
		dst[3] = 0
	}
	dst[4] = p.RotateSpan
	dst[5] = p.PadMin
	dst[6] = p.JitterMinMs
	dst[7] = p.JitterMaxMs
	dst[8] = 0
}

func decodeObfsParams(src []byte) (ObfsParams, error) {
	if len(src) < 5 {
		return ObfsParams{}, fmt.Errorf("invalid obfs params length")
	}
	p := ObfsParams{
		PadMax:        src[0],
		RotateMin:     src[1],
		RotateMax:     src[2],
		DynamicRotate: src[3] == 1,
		RotateSpan:    src[4],
	}
	if len(src) >= 8 {
		p.PadMin = src[5]
		p.JitterMinMs = src[6]
		p.JitterMaxMs = src[7]
	}
	return p.Normalize()
}
