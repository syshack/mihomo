package cf

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	TypeOpen    byte = 1
	TypeData    byte = 2
	TypeClose   byte = 3
	TypeOpenOK  byte = 4
	TypeOpenErr byte = 5
	TypeUDPOpen byte = 6
	TypeUDPData byte = 7
	TypePing    byte = 8
	TypePong    byte = 9
)

const HeaderLen = 13

type Frame struct {
	Type    byte
	ConnID  uint32
	Nonce   uint32
	Payload []byte
}

func marshalFrame(f Frame, secret []byte) ([]byte, error) {
	return marshalFrameWithParams(f, secret, defaultObfsParams())
}

func marshalFrameWithParams(f Frame, secret []byte, params ObfsParams) ([]byte, error) {
	return appendFrameWithParams(nil, f, secret, params)
}

func appendFrameWithParams(dst []byte, f Frame, secret []byte, params ObfsParams) ([]byte, error) {
	start := len(dst)
	dst = append(dst, make([]byte, HeaderLen)...)
	dst[start] = f.Type
	binary.BigEndian.PutUint32(dst[start+1:start+5], f.ConnID)
	binary.BigEndian.PutUint32(dst[start+9:start+13], f.Nonce)

	payloadStart := len(dst)
	dst, err := appendEncodePayloadWithParams(dst, f.Payload, secret, f.Nonce, params)
	if err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint32(dst[start+5:start+9], uint32(len(dst)-payloadStart))
	return dst, nil
}

func readFrame(r io.Reader, secret []byte) (Frame, error) {
	return readFrameWithParams(r, secret, defaultObfsParams())
}

func readFrameWithParams(r io.Reader, secret []byte, params ObfsParams) (Frame, error) {
	h := make([]byte, HeaderLen)
	if _, err := io.ReadFull(r, h); err != nil {
		return Frame{}, err
	}
	l := binary.BigEndian.Uint32(h[5:9])
	if l > 16*1024*1024 {
		return Frame{}, fmt.Errorf("frame too large: %d", l)
	}
	b := make([]byte, int(l))
	if _, err := io.ReadFull(r, b); err != nil {
		return Frame{}, err
	}
	nonce := binary.BigEndian.Uint32(h[9:13])
	p, err := decodePayloadWithParams(b, secret, nonce, params)
	if err != nil {
		return Frame{}, err
	}
	return Frame{Type: h[0], ConnID: binary.BigEndian.Uint32(h[1:5]), Nonce: nonce, Payload: p}, nil
}
