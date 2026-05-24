package cf

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/bits"
)

const maxPad = 8

type ObfsParams struct {
	PadMin        uint8
	PadMax        uint8
	RotateMin     uint8
	RotateMax     uint8
	DynamicRotate bool
	RotateSpan    uint8
	JitterMinMs   uint8
	JitterMaxMs   uint8
}

func defaultObfsParams() ObfsParams {
	return ObfsParams{
		PadMin:        0,
		PadMax:        maxPad,
		RotateMin:     1,
		RotateMax:     7,
		DynamicRotate: false,
		RotateSpan:    1,
		JitterMinMs:   0,
		JitterMaxMs:   0,
	}
}

func (p ObfsParams) Normalize() (ObfsParams, error) {
	if p.PadMax == 0 {
		p.PadMax = maxPad
	}
	if p.PadMax > 64 {
		return ObfsParams{}, fmt.Errorf("pad max out of range: %d", p.PadMax)
	}
	if p.PadMin > p.PadMax {
		return ObfsParams{}, fmt.Errorf("pad min out of range: %d > %d", p.PadMin, p.PadMax)
	}
	if p.RotateMin == 0 {
		p.RotateMin = 1
	}
	if p.RotateMax == 0 {
		p.RotateMax = 7
	}
	if p.RotateMin > 7 || p.RotateMax > 7 || p.RotateMin > p.RotateMax {
		return ObfsParams{}, fmt.Errorf("rotate range invalid: %d-%d", p.RotateMin, p.RotateMax)
	}
	if p.RotateSpan == 0 {
		p.RotateSpan = 1
	}
	if p.RotateSpan > 32 {
		return ObfsParams{}, fmt.Errorf("rotate span out of range: %d", p.RotateSpan)
	}
	if p.JitterMaxMs > 200 {
		return ObfsParams{}, fmt.Errorf("jitter max out of range: %d", p.JitterMaxMs)
	}
	if p.JitterMinMs > p.JitterMaxMs {
		return ObfsParams{}, fmt.Errorf("jitter range invalid: %d-%d", p.JitterMinMs, p.JitterMaxMs)
	}
	return p, nil
}

func negotiateObfsParams(client ObfsParams, server ObfsParams) (ObfsParams, error) {
	c, err := client.Normalize()
	if err != nil {
		return ObfsParams{}, err
	}
	s, err := server.Normalize()
	if err != nil {
		return ObfsParams{}, err
	}

	n := ObfsParams{}
	n.PadMin = maxU8(c.PadMin, s.PadMin)
	n.PadMax = minU8(c.PadMax, s.PadMax)
	if n.PadMin > n.PadMax {
		return ObfsParams{}, fmt.Errorf("pad range has no overlap: client=%d-%d server=%d-%d", c.PadMin, c.PadMax, s.PadMin, s.PadMax)
	}
	n.RotateMin = maxU8(c.RotateMin, s.RotateMin)
	n.RotateMax = minU8(c.RotateMax, s.RotateMax)
	if n.RotateMin > n.RotateMax {
		return ObfsParams{}, fmt.Errorf("rotate range has no overlap: client=%d-%d server=%d-%d", c.RotateMin, c.RotateMax, s.RotateMin, s.RotateMax)
	}
	n.DynamicRotate = c.DynamicRotate && s.DynamicRotate
	n.RotateSpan = minU8(c.RotateSpan, s.RotateSpan)
	if n.RotateSpan == 0 {
		n.RotateSpan = 1
	}
	n.JitterMinMs = maxU8(c.JitterMinMs, s.JitterMinMs)
	n.JitterMaxMs = minU8(c.JitterMaxMs, s.JitterMaxMs)
	if n.JitterMinMs > n.JitterMaxMs {
		return ObfsParams{}, fmt.Errorf("jitter range has no overlap: client=%d-%d server=%d-%d", c.JitterMinMs, c.JitterMaxMs, s.JitterMinMs, s.JitterMaxMs)
	}

	return n.Normalize()
}

func encodePayload(payload []byte, secret []byte, nonce uint32) ([]byte, error) {
	return encodePayloadWithParams(payload, secret, nonce, defaultObfsParams())
}

func encodePayloadWithParams(payload []byte, secret []byte, nonce uint32, params ObfsParams) ([]byte, error) {
	return appendEncodePayloadWithParams(nil, payload, secret, nonce, params)
}

func appendEncodePayloadWithParams(dst []byte, payload []byte, secret []byte, nonce uint32, params ObfsParams) ([]byte, error) {
	params, err := params.Normalize()
	if err != nil {
		return nil, err
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("empty secret")
	}

	maxNow := int(params.PadMax)
	if params.DynamicRotate {
		delta := int((nonce / uint32(params.RotateSpan)) % uint32(params.PadMax+1))
		maxNow = max(1, int(params.PadMax)-delta)
	}

	padMinNow := int(params.PadMin)
	if params.DynamicRotate {
		padMinNow = minInt(padMinNow, maxNow)
	}
	lead, err := randByteRange(padMinNow, maxNow)
	if err != nil {
		return nil, err
	}
	tail, err := randByteRange(padMinNow, maxNow)
	if err != nil {
		return nil, err
	}
	realLen := len(payload)
	startLen := len(dst)
	dst = append(dst, make([]byte, 4+1+1+int(lead)+realLen+int(tail))...)
	out := dst[startLen:]
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

	rangeWidth := params.RotateMax - params.RotateMin + 1
	rot := uint((nonce % uint32(rangeWidth)) + uint32(params.RotateMin))
	secretIdx := int(nonce) % len(secret)
	for i := 0; i < len(out); i++ {
		b := out[i] ^ secret[secretIdx]
		out[i] = bits.RotateLeft8(b, int(rot))
		secretIdx++
		if secretIdx == len(secret) {
			secretIdx = 0
		}
	}
	return dst, nil
}

func decodePayload(payload []byte, secret []byte, nonce uint32) ([]byte, error) {
	return decodePayloadWithParams(payload, secret, nonce, defaultObfsParams())
}

func decodePayloadWithParams(payload []byte, secret []byte, nonce uint32, params ObfsParams) ([]byte, error) {
	params, err := params.Normalize()
	if err != nil {
		return nil, err
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("empty secret")
	}
	if len(payload) < 6 {
		return nil, fmt.Errorf("payload too short")
	}
	buf := make([]byte, len(payload))
	copy(buf, payload)
	rangeWidth := params.RotateMax - params.RotateMin + 1
	rot := uint((nonce % uint32(rangeWidth)) + uint32(params.RotateMin))
	secretIdx := int(nonce) % len(secret)
	for i := 0; i < len(buf); i++ {
		b := bits.RotateLeft8(buf[i], -int(rot))
		buf[i] = b ^ secret[secretIdx]
		secretIdx++
		if secretIdx == len(secret) {
			secretIdx = 0
		}
	}

	realLen := int(binary.BigEndian.Uint32(buf[0:4]))
	lead := int(buf[4])
	tail := int(buf[5])

	maxNow := int(params.PadMax)
	if params.DynamicRotate {
		delta := int((nonce / uint32(params.RotateSpan)) % uint32(params.PadMax+1))
		maxNow = max(1, int(params.PadMax)-delta)
	}
	if lead > maxNow || tail > maxNow {
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

func randByteRange(min, max int) (byte, error) {
	if min < 0 || max < min || max > 255 {
		return 0, fmt.Errorf("invalid random range")
	}
	if min == max {
		return byte(min), nil
	}
	b, err := randByte(max - min + 1)
	if err != nil {
		return 0, err
	}
	return byte(min) + b, nil
}

func minU8(a, b uint8) uint8 {
	if a < b {
		return a
	}
	return b
}

func maxU8(a, b uint8) uint8 {
	if a > b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
