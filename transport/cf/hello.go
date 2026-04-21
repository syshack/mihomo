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
)

func writeClientHello(conn net.Conn, secret []byte) error {
	if len(secret) == 0 {
		return fmt.Errorf("empty secret")
	}
	hello := make([]byte, clientHelloLen)
	copy(hello[0:4], []byte(clientHelloMagic))
	hello[4] = clientHelloVer
	hello[5] = 0
	binary.BigEndian.PutUint16(hello[6:8], 0)
	if _, err := rand.Read(hello[8:24]); err != nil {
		return err
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(hello[:24])
	sig := mac.Sum(nil)
	copy(hello[24:40], sig[:16])

	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := conn.Write(hello)
	_ = conn.SetWriteDeadline(time.Time{})
	return err
}

func consumeClientHelloReader(br *bufio.Reader, secret []byte) (*bufio.Reader, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("empty secret")
	}
	hello := make([]byte, clientHelloLen)
	if _, err := io.ReadFull(br, hello); err != nil {
		return nil, err
	}
	if string(hello[0:4]) != clientHelloMagic {
		return nil, fmt.Errorf("invalid hello magic")
	}
	if hello[4] != clientHelloVer {
		return nil, fmt.Errorf("unsupported hello version: %d", hello[4])
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(hello[:24])
	want := mac.Sum(nil)
	if !hmac.Equal(hello[24:40], want[:16]) {
		return nil, fmt.Errorf("invalid hello signature")
	}
	return br, nil
}
