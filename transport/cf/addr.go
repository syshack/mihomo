package cf

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

func EncodeAddress(addr string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	portN, err := strconv.Atoi(portStr)
	if err != nil || portN < 1 || portN > 65535 {
		return nil, fmt.Errorf("invalid port: %s", portStr)
	}
	port := uint16(portN)

	h := strings.Trim(host, "[]")
	if ip := net.ParseIP(h); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out := make([]byte, 1+4+2)
			out[0] = 1
			copy(out[1:5], v4)
			binary.BigEndian.PutUint16(out[5:7], port)
			return out, nil
		}
		v6 := ip.To16()
		out := make([]byte, 1+16+2)
		out[0] = 4
		copy(out[1:17], v6)
		binary.BigEndian.PutUint16(out[17:19], port)
		return out, nil
	}
	if len(h) == 0 || len(h) > 255 {
		return nil, fmt.Errorf("invalid domain len")
	}
	out := make([]byte, 1+1+len(h)+2)
	out[0] = 3
	out[1] = byte(len(h))
	copy(out[2:2+len(h)], []byte(h))
	binary.BigEndian.PutUint16(out[2+len(h):], port)
	return out, nil
}
