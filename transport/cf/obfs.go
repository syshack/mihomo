package cf

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/bits"
)

const maxPad = 8

func encodePayload(payload []byte, secret []byte, nonce uint32) ([]byte, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("empty secret")
	}
	lead, err := randByte(maxPad + 1)
	if err != nil {
		return nil, err
	}
	tail, err := randByte(maxPad + 1)
	if err != nil {
		return nil, err
	}
	realLen := len(payload)
	out := make([]byte, 4+1+1+int(lead)+realLen+int(tail))
	binary.BigEndian.PutUint32(out[0:4], uint32(realLen))
	out[4] = lead
	out[5] = tail
	if lead > 0 {
		if _, err := rand.Read(out[6 : 6+int(lead)]); err != nil {
			return nil, err
		}
	}
	copy(out[6+int(lead):6+int(lead)+realLen], payload)
	if tail > 0 {
		if _, err := rand.Read(out[6+int(lead)+realLen:]); err != nil {
			return nil, err
		}
	}

	rot := uint((nonce % 7) + 1)
	for i := 0; i < len(out); i++ {
		b := out[i] ^ secret[(i+int(nonce))%len(secret)]
		out[i] = bits.RotateLeft8(b, int(rot))
	}
	return out, nil
}

func decodePayload(payload []byte, secret []byte, nonce uint32) ([]byte, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("empty secret")
	}
	if len(payload) < 6 {
		return nil, fmt.Errorf("payload too short")
	}
	buf := make([]byte, len(payload))
	copy(buf, payload)
	rot := uint((nonce % 7) + 1)
	for i := 0; i < len(buf); i++ {
		b := bits.RotateLeft8(buf[i], -int(rot))
		buf[i] = b ^ secret[(i+int(nonce))%len(secret)]
	}

	realLen := int(binary.BigEndian.Uint32(buf[0:4]))
	lead := int(buf[4])
	tail := int(buf[5])
	if lead > maxPad || tail > maxPad {
		return nil, fmt.Errorf("pad out of range")
	}
	start := 6 + lead
	end := start + realLen
	if start < 0 || end > len(buf)-tail {
		return nil, fmt.Errorf("invalid frame boundaries")
	}
	out := make([]byte, realLen)
	copy(out, buf[start:end])
	return out, nil
}

func randByte(max int) (byte, error) {
	if max <= 0 || max > 256 {
		return 0, fmt.Errorf("invalid random max")
	}
	b := make([]byte, 1)
	if _, err := rand.Read(b); err != nil {
		return 0, err
	}
	return byte(int(b[0]) % max), nil
}
