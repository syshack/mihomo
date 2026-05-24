package cf

import (
	"bytes"
	"testing"
)

func TestEncodeDecodePayloadWithParamsRoundTrip(t *testing.T) {
	params := ObfsParams{
		PadMin:        1,
		PadMax:        4,
		RotateMin:     2,
		RotateMax:     6,
		DynamicRotate: true,
		RotateSpan:    3,
	}
	secret := []byte("test-secret")
	payload := []byte("hello through android cf")
	nonce := uint32(42)

	enc, err := encodePayloadWithParams(payload, secret, nonce, params)
	if err != nil {
		t.Fatalf("encodePayloadWithParams returned error: %v", err)
	}
	dec, err := decodePayloadWithParams(enc, secret, nonce, params)
	if err != nil {
		t.Fatalf("decodePayloadWithParams returned error: %v", err)
	}
	if !bytes.Equal(dec, payload) {
		t.Fatalf("decoded payload = %q, want %q", dec, payload)
	}
}
