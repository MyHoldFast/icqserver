package main

import (
	"strconv"
	"strings"
)

func (s *Session) snac17(sub uint16, reqid uint32, data []byte) {
	switch sub {
	case SnIesReqNewUin:
		s.handleRegNewUin(data)
	case SnIesAuthRequest:
		s.handleMD5AuthRequest(data)
	case SnIesAuthLogin:
		s.handleMD5AuthLogin(data, reqid)
	default:
	}
}

func (s *Session) handleMD5AuthRequest(data []byte) {
	tlvs := parseTLVs(data)
	uinB, ok := tlvs[0x0001]
	if !ok || !isAllDigits(string(uinB)) {
		return
	}
	s.md5AuthKey = makeMD5AuthKey()
	keyB := []byte(s.md5AuthKey)
	payload := append(beU16(uint16(len(keyB))), keyB...)
	s.sendSnac(SnTypRegistration, SnIesAuthKey, payload, noReqID, 0)
}

func isAllDigits(str string) bool {
	if str == "" {
		return false
	}
	for _, c := range str {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func (s *Session) handleMD5AuthLogin(data []byte, reqid uint32) {
	tlvs := parseTLVs(data)
	uin := string(tlvs[0x0001])
	digest, hasDigest := tlvs[0x0025]
	_, newMethod := tlvs[0x004C]

	fail := func(errcode uint16) {
		payload := makeTLV(8, beU16(errcode))
		s.sendSnac(SnTypRegistration, SnIesLoginReply, payload, int64(0), 0)
		s.stop()
	}

	if !isAllDigits(uin) || !hasDigest || len(digest) != 16 || s.md5AuthKey == "" {
		fail(0x0006)
		return
	}
	password, ok := s.server.Storage.GetPassword(uin)
	if !ok {
		fail(0x0007)
		return
	}
	expected := aimMD5Digest(s.md5AuthKey, password, newMethod)
	if !bytesEqual(expected, digest) {
		fail(0x0005)
		return
	}

	cookie := makeCookie(uin)
	s.server.setPendingCookie(cookie, uin)
	hostPort := s.bosHostPort()
	payload := append(makeTLV(0x008E, []byte{0x00}), makeTLV(1, []byte(uin))...)
	payload = append(payload, makeTLV(5, hostPort)...)
	payload = append(payload, makeTLV(6, cookie)...)
	s.sendSnac(SnTypRegistration, SnIesLoginReply, payload, int64(0), 0)
	s.sendFlap(4, nil)
	s.stop()
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (s *Session) handleRegNewUin(data []byte) {
	tlvs := parseTLVs(data)
	tlv1, ok := tlvs[0x0001]
	if !ok || len(tlv1) < 40 {
		s.sendRegRefused(0)
		return
	}
	pos := 4 * 4
	reqCookie := getLE32(tlv1, pos)
	pos += 4
	pos += 5 * 4

	if pos+2 > len(tlv1) {
		s.sendRegRefused(reqCookie)
		return
	}
	pwLen := int(getLE16(tlv1, pos))
	pos += 2
	end := pos + pwLen
	if end > len(tlv1) {
		end = len(tlv1)
	}
	pwRaw := tlv1[pos:end]
	password := strings.TrimRight(string(pwRaw), "\x00")

	if !s.server.RegistrationEnabled {
		s.sendRegRefused(reqCookie)
		return
	}
	if password == "" {
		s.sendRegRefused(reqCookie)
		return
	}
	newUin, err := s.server.Storage.RegisterNewUser(password)
	if err != nil {
		s.sendRegRefused(reqCookie)
		return
	}
	s.sendNewUin(newUin, reqCookie)
}

func (s *Session) sendNewUin(newUin string, reqCookie uint32) {
	peerIP, peerPort := remoteAddrParts(s.conn)
	ipInt := ipToUint32(peerIP)

	var reply []byte
	reply = append(reply, leU32(0)...)
	reply = append(reply, leU16(0x002D)...)
	reply = append(reply, leU16(0x0003)...)
	reply = append(reply, leU32(uint32(peerPort))...)
	reply = append(reply, leU32(ipInt)...)
	reply = append(reply, leU32(0x04000000)...)
	reply = append(reply, leU32(reqCookie)...)
	reply = append(reply, leU32(0)...)
	reply = append(reply, leU32(0)...)
	reply = append(reply, leU32(0)...)
	reply = append(reply, leU32(0)...)
	newUinInt, _ := strconv.ParseUint(newUin, 10, 32)
	reply = append(reply, leU32(uint32(newUinInt))...)
	reply = append(reply, leU32(reqCookie)...)

	tlvValue := append(leU16(uint16(len(reply))), reply...)
	payload := makeTLV(0x0001, tlvValue)
	s.sendSnac(SnTypRegistration, SnIesSrvNewUin, payload, int64(0), 0)
}

func (s *Session) sendRegRefused(reqCookie uint32) {
	peerIP, peerPort := remoteAddrParts(s.conn)
	ipInt := ipToUint32(peerIP)

	var reply []byte
	reply = append(reply, beU32(0)...)
	reply = append(reply, beU16(0)...)
	reply = append(reply, beU32(reqCookie)...)
	reply = append(reply, beU32(uint32(peerPort))...)
	reply = append(reply, beU32(ipInt)...)
	reply = append(reply, beU32(0x00000004)...)
	reply = append(reply, beU32(reqCookie)...)
	reply = append(reply, beU32(0x400464F8)...)

	payload := append(beU16(0x0005), makeTLV(0x0021, reply)...)
	s.sendSnac(SnTypRegistration, SnIesError, payload, int64(0), 0)
}
