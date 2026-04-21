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
	enc, err := encodePayload(f.Payload, secret, f.Nonce)
	if err != nil {
		return nil, err
	}
	out := make([]byte, HeaderLen+len(enc))
	out[0] = f.Type
	binary.BigEndian.PutUint32(out[1:5], f.ConnID)
	binary.BigEndian.PutUint32(out[5:9], uint32(len(enc)))
	binary.BigEndian.PutUint32(out[9:13], f.Nonce)
	copy(out[HeaderLen:], enc)
	return out, nil
}

func readFrame(r io.Reader, secret []byte) (Frame, error) {
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
	p, err := decodePayload(b, secret, nonce)
	if err != nil {
		return Frame{}, err
	}
	return Frame{Type: h[0], ConnID: binary.BigEndian.Uint32(h[1:5]), Nonce: nonce, Payload: p}, nil
}
