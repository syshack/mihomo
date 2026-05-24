package cf

import (
	"bytes"
	"testing"
)

func TestAppendFrameWithParamsUsesDestinationBuffer(t *testing.T) {
	params := ObfsParams{PadMin: 0, PadMax: 0, RotateMin: 1, RotateMax: 7}
	secret := []byte("test-secret")
	f := Frame{Type: TypeData, ConnID: 7, Nonce: 11, Payload: []byte("payload")}
	dst := make([]byte, 0, 1024)
	base := &dst[:1][0]

	out, err := appendFrameWithParams(dst, f, secret, params)
	if err != nil {
		t.Fatalf("appendFrameWithParams returned error: %v", err)
	}
	if &out[0] != base {
		t.Fatalf("appendFrameWithParams did not reuse destination buffer")
	}

	got, err := readFrameWithParams(bytes.NewReader(out), secret, params)
	if err != nil {
		t.Fatalf("readFrameWithParams returned error: %v", err)
	}
	if got.Type != f.Type || got.ConnID != f.ConnID || got.Nonce != f.Nonce || !bytes.Equal(got.Payload, f.Payload) {
		t.Fatalf("round trip frame = %+v, want %+v", got, f)
	}
}
