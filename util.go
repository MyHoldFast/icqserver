package main

import "net"

func remoteAddrParts(conn net.Conn) (string, int) {
	addr := conn.RemoteAddr()
	if addr == nil {
		return "127.0.0.1", 0
	}
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "127.0.0.1", 0
	}
	port := 0
	for _, c := range portStr {
		if c < '0' || c > '9' {
			port = 0
			break
		}
		port = port*10 + int(c-'0')
	}
	return host, port
}

func hostOnly(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return ""
	}
	return host
}

func ipToUint32(ip string) uint32 {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return 0
	}
	v4 := parsed.To4()
	if v4 == nil {
		return 0
	}
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
}
