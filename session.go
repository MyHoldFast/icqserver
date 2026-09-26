package main

import (
	"bufio"
	"encoding/binary"
	"io"
	"log"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const noReqID int64 = -1

type Session struct {
	conn   net.Conn
	reader *bufio.Reader
	server *Server

	writeMu sync.Mutex
	seq     uint16

	uin           string
	authenticated bool
	status        uint32
	loginTs       time.Time

	xstatusRaw []byte
	caps       []byte
	dcInfo     []byte

	running int32

	md5AuthKey string
	snacReqID  uint32

	ssiGroupRemap    map[uint16]uint16
	rosterSent       bool
	offlineDelivered bool

	motdSent            bool
	pendingRosterReqID  *uint32
	bosRightsSent       bool
	clientReadySeen     bool
	rateInfoSent        bool
	initialSelfInfoSent bool
	statsSent           bool

	ssiActivated bool

	icbmFlags map[uint16]uint32

	closeOnce sync.Once
}

func NewSession(conn net.Conn, server *Server) *Session {
	return &Session{
		conn:          conn,
		reader:        bufio.NewReader(conn),
		server:        server,
		status:        StatusOffline,
		seq:           uint16(rand.Intn(0x7FFF) + 1),
		running:       1,
		ssiGroupRemap: map[uint16]uint16{},
		icbmFlags:     defaultIcbmFlags(),
	}
}

func (s *Session) isRunning() bool { return atomic.LoadInt32(&s.running) != 0 }
func (s *Session) stop()           { atomic.StoreInt32(&s.running, 0) }

func (s *Session) spawn(f func()) {
	if !s.isRunning() || s.uin == "" {
		return
	}
	go func() {
		defer func() { recover() }()
		f()
	}()
}

func (s *Session) sendFlap(channel byte, payload []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.seq = (s.seq + 1) & 0xFFFF
	_, err := s.conn.Write(packFlap(channel, s.seq, payload))
	return err
}

func (s *Session) sendSnac(fam, sub uint16, payload []byte, reqid int64, flags uint16) error {
	var r uint32
	if reqid < 0 {

		r = atomic.AddUint32(&s.snacReqID, 1)
	} else {
		r = uint32(reqid)
	}
	return s.sendFlap(2, makeSnac(fam, sub, flags, r, payload))
}

func (s *Session) readDeadline() time.Time {
	if s.authenticated {
		return time.Time{}
	}
	return time.Now().Add(ConnIdleTimeoutSec * time.Second)
}

func (s *Session) recvFlap() (byte, uint16, []byte, error) {
	s.conn.SetReadDeadline(s.readDeadline())
	hdr := make([]byte, 6)
	if _, err := io.ReadFull(s.reader, hdr); err != nil {
		return 0, 0, nil, err
	}
	ch := hdr[1]
	seq := binary.BigEndian.Uint16(hdr[2:4])
	size := binary.BigEndian.Uint16(hdr[4:6])
	var body []byte
	if size > 0 {
		body = make([]byte, size)
		s.conn.SetReadDeadline(s.readDeadline())
		if _, err := io.ReadFull(s.reader, body); err != nil {
			return 0, 0, nil, err
		}
	}
	return ch, seq, body, nil
}

func (s *Session) Run() {
	defer s.cleanup()
	if err := s.sendFlap(1, []byte{0x00, 0x00, 0x00, 0x01}); err != nil {
		return
	}
	for s.isRunning() {
		ch, _, payload, err := s.recvFlap()
		if err != nil {
			return
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[%s] panic handling packet: %v", s.uin, r)
				}
			}()
			switch ch {
			case 1:
				s.handleCh1(payload)
			case 2:
				s.handleCh2(payload)
			case 4:
				s.stop()
			case 5:
			default:
			}
		}()
	}
}

func (s *Session) cleanup() {
	s.closeOnce.Do(func() {
		s.stop()
		if s.uin != "" {
			current := s.server.getSession(s.uin)
			if current == s {

				s.server.deleteSession(s.uin)
				s.status = StatusOffline
				func() {
					defer func() {
						if r := recover(); r != nil {
							log.Printf("[%s] offline broadcast panic: %v", s.uin, r)
						}
					}()
					s.broadcastOfflineSync()
				}()
			} else {
				log.Printf("[%s] session closed but not current, skipping offline broadcast", s.uin)
			}

			s.uin = ""
		}
		s.conn.Close()
	})
}

func (s *Session) handleCh1(payload []byte) {
	if len(payload) < 4 {
		return
	}
	tlvs := parseTLVs(payload[4:])
	if v, ok := tlvs[6]; ok {
		s.handleBosAuth(v)
	} else if uinTLV, ok0 := tlvs[1]; ok0 {
		if digest, ok25 := tlvs[0x0025]; ok25 {
			_, newMethod := tlvs[0x004C]
			s.handleStage1MD5Auth(uinTLV, digest, newMethod)
		} else if passTLV, ok2 := tlvs[2]; ok2 {
			s.handleStage1Auth(uinTLV, passTLV)
		}
	}
}

func (s *Session) handleStage1MD5Auth(uinTLV, digest []byte, newMethod bool) {
	uin := string(uinTLV)

	fail := func(errcode uint16) {
		desc := []byte("Invalid password")
		errPayload := append(makeTLV(1, uinTLV), makeTLV(4, desc)...)
		errPayload = append(errPayload, makeTLV(8, beU16(errcode))...)
		s.sendFlap(4, errPayload)
		s.stop()
	}

	if !isAllDigits(uin) || len(digest) != 16 || s.md5AuthKey == "" {
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
	reply := append(makeTLV(1, uinTLV), makeTLV(5, hostPort)...)
	reply = append(reply, makeTLV(6, cookie)...)
	s.sendFlap(4, reply)
	s.stop()
}

func (s *Session) handleStage1Auth(uinTLV, passTLV []byte) {
	uin := string(uinTLV)
	if !s.server.Storage.CheckAuth(uin, passTLV) {
		desc := []byte("Invalid password")
		errPayload := append(makeTLV(1, uinTLV), makeTLV(4, desc)...)
		errPayload = append(errPayload, makeTLV(8, beU16(0x0005))...)
		s.sendFlap(4, errPayload)
		s.stop()
		return
	}
	cookie := makeCookie(uin)
	s.server.setPendingCookie(cookie, uin)
	hostPort := s.bosHostPort()
	reply := append(makeTLV(1, uinTLV), makeTLV(5, hostPort)...)
	reply = append(reply, makeTLV(6, cookie)...)
	s.sendFlap(4, reply)
	s.stop()
}

func (s *Session) bosHostPort() []byte {
	sockIP := hostOnly(s.conn.LocalAddr())
	peerIP := hostOnly(s.conn.RemoteAddr())
	host := pickBosHost(s.server.BosHost, sockIP, peerIP)
	port := s.server.BosPort
	if port == 0 {
		port = s.server.Port
	}
	return []byte(host + ":" + strconv.Itoa(port))
}

func (s *Session) handleBosAuth(cookie []byte) {
	uin, ok := s.server.popPendingCookie(string(cookie))
	if !ok {
		s.stop()
		return
	}
	s.uin = uin
	s.authenticated = true
	s.server.Storage.EnsureDefaultGroups(uin)
	s.server.Storage.FixOrphanContacts(uin)
	s.status = StatusOnline
	s.loginTs = time.Now()

	old := s.server.replaceSession(uin, s)
	if old != nil && old != s {
		old.stop()
		old.conn.Close()
	}

	var famPayload []byte
	for _, id := range ServerFamilyIDs {
		famPayload = append(famPayload, beU16(id)...)
	}
	s.sendSnac(0x0001, 0x0003, famPayload, noReqID, 0)

	s.sendFamilyVersionsMotdAndRate()
}

func (s *Session) sendFamilyVersions() {
	var p []byte
	for _, fv := range ServerFamilies {
		p = append(p, beU16(fv.Fam)...)
		p = append(p, beU16(fv.Ver)...)
	}
	s.sendSnac(0x0001, 0x0018, p, noReqID, 0)
}

func (s *Session) sendMotd() {
	payload := append(beU16(5), makeTLV(0x0002, beU16(0x001E))...)
	payload = append(payload, makeTLV(0x0003, beU16(0x04B0))...)
	s.sendSnac(0x0001, 0x0013, payload, noReqID, 0)
	s.motdSent = true
}

func (s *Session) sendFamilyVersionsMotdAndRate() {
	s.sendFamilyVersions()
	s.sendMotd()

	s.sendSnac(0x0001, 0x0007, basicRateInfo, int64(6), 0)
	s.rateInfoSent = true
}

func (s *Session) handleCh2(payload []byte) {
	if len(payload) < 10 {
		return
	}
	fam := binary.BigEndian.Uint16(payload[0:2])
	sub := binary.BigEndian.Uint16(payload[2:4])
	reqid := binary.BigEndian.Uint32(payload[6:10])
	data := payload[10:]
	s.dispatchSnac(fam, sub, reqid, data)
}

func (s *Session) dispatchSnac(fam, sub uint16, reqid uint32, data []byte) {
	switch fam {
	case 0x0001:
		s.snac01(sub, reqid, data)
	case 0x0002:
		s.snac02(sub, reqid, data)
	case 0x0003:
		s.snac03(sub, reqid, data)
	case 0x0004:
		s.snac04(sub, reqid, data)
	case 0x0009:
		s.snac09(sub, reqid, data)
	case 0x0013:
		s.snac13(sub, reqid, data)
	case 0x0015:
		s.snac15(sub, reqid, data)
	case SnTypRegistration:
		s.snac17(sub, reqid, data)
	default:
	}
}

func (s *Session) snac01(sub uint16, reqid uint32, data []byte) {
	switch sub {
	case 0x0002:
		s.clientReadySeen = true
		s.broadcastOnline()
		s.deliverPendingAuthRequests()
		if !s.statsSent {
			s.sendSnac(0x000B, 0x0002, beU16(0x0001), noReqID, 0)
			s.statsSent = true
		}
		s.flushPendingRoster()
	case 0x000E:
		initial := !s.initialSelfInfoSent
		s.handleSelfInfo(int64(reqid), initial)
		if initial {
			s.initialSelfInfoSent = true
			if !s.statsSent {
				s.sendSnac(0x000B, 0x0002, beU16(0x0001), noReqID, 0)
				s.statsSent = true
			}
		}
	case 0x0017:

		if s.rateInfoSent {
			return
		}
		s.sendFamilyVersions()
		if !s.motdSent {
			s.sendMotd()
		}
	case 0x0006:
		if s.rateInfoSent {
			return
		}
		if !s.motdSent {
			s.sendMotd()
		}
		s.sendSnac(0x0001, 0x0007, basicRateInfo, int64(reqid), 0)
		s.rateInfoSent = true
	case 0x0008:
	case 0x001E:

		tlvs := parseTLVs(data)
		if raw, ok := tlvs[0x0006]; ok && len(raw) >= 4 {
			newStatus := getBE32(raw, 0)
			if newStatus != s.status {
				s.status = newStatus
				s.broadcastPresence()
			}
		}

		if dc, ok := tlvs[0x000C]; ok {
			s.dcInfo = dc
			s.handleSelfInfo(noReqID, false)
		}
	default:
	}
}

func (s *Session) flushPendingRoster() {
	if s.pendingRosterReqID == nil {
		return
	}
	pr := *s.pendingRosterReqID
	s.pendingRosterReqID = nil
	s.sendRoster(int64(pr))
}

func (s *Session) handleSelfInfo(reqid int64, initial bool) {
	uinB := []byte(s.uin)
	status := s.status
	if status == StatusOffline {
		status = StatusOnline
	}
	ipInt := peerIPUint32(s.conn)
	var signon uint32
	if !s.loginTs.IsZero() {
		signon = uint32(s.loginTs.Unix())
	} else {
		signon = uint32(time.Now().Unix())
	}
	member := signon

	if initial {
		dc := pad37(s.dcInfo)
		tlvs := makeTLV(0x0001, beU16(0x0050))
		tlvs = append(tlvs, makeTLV(0x000C, dc)...)
		tlvs = append(tlvs, makeTLV(0x000A, beU32(ipInt))...)
		tlvs = append(tlvs, makeTLV(0x000F, beU32(0))...)
		tlvs = append(tlvs, makeTLV(0x0003, beU32(signon))...)
		tlvs = append(tlvs, makeTLV(0x000A, beU32(ipInt))...)
		tlvs = append(tlvs, makeTLV(0x001E, beU32(0))...)
		tlvs = append(tlvs, makeTLV(0x0005, beU32(member))...)
		userInfo := append([]byte{byte(len(uinB))}, uinB...)
		userInfo = append(userInfo, beU16(0)...)
		userInfo = append(userInfo, beU16(8)...)
		userInfo = append(userInfo, tlvs...)
		s.sendSnac(0x0001, 0x000F, userInfo, reqid, 0)
	} else {
		tlvs := makeTLV(0x0001, beU16(0x0050))
		tlvs = append(tlvs, makeTLV(0x0006, beU32(status))...)
		tlvs = append(tlvs, makeTLV(0x000F, beU32(0))...)
		tlvs = append(tlvs, makeTLV(0x0003, beU32(signon))...)
		tlvs = append(tlvs, makeTLV(0x000A, beU32(ipInt))...)
		tlvs = append(tlvs, makeTLV(0x001E, beU32(0))...)
		tlvs = append(tlvs, makeTLV(0x0005, beU32(member))...)
		userInfo := append([]byte{byte(len(uinB))}, uinB...)
		userInfo = append(userInfo, beU16(0)...)
		userInfo = append(userInfo, beU16(7)...)
		userInfo = append(userInfo, tlvs...)
		ext := append(beU16(0x0006), beU16(0x0001)...)
		ext = append(ext, beU16(0x0002)...)
		ext = append(ext, beU16(0x0003)...)
		full := append(ext, userInfo...)
		s.sendSnac(0x0001, 0x000F, full, reqid, 0x8000)
	}
}

func (s *Session) snac02(sub uint16, reqid uint32, data []byte) {
	switch sub {
	case 0x0002:
		rights := makeTLV(0x0001, beU16(0x0400))
		rights = append(rights, makeTLV(0x0002, beU16(0x000E))...)
		rights = append(rights, makeTLV(0x0003, beU16(0x000A))...)
		rights = append(rights, makeTLV(0x0004, beU16(0x1000))...)
		rights = append(rights, makeTLV(0x0005, beU16(0x0080))...)
		s.sendSnac(0x0002, 0x0003, rights, int64(reqid), 0)
	case 0x0004:
		tlvs := parseTLVs(data)
		if v, ok := tlvs[0x0005]; ok {
			s.caps = v
		}
		if v, ok := tlvs[0x001D]; ok {
			s.xstatusRaw = v
		} else {
			s.xstatusRaw = nil
		}
		if s.uin != "" {
			s.broadcastPresence()
		}
	default:
	}
}

func (s *Session) snac09(sub uint16, reqid uint32, data []byte) {
	if sub == 0x0002 {
		rights := makeTLV(0x0002, beU16(0x00C8))
		rights = append(rights, makeTLV(0x0001, beU16(0x00C8))...)
		s.sendSnac(0x0009, 0x0003, rights, int64(reqid), 0)

		s.bosRightsSent = true
		s.flushPendingRoster()
	}
}

func (s *Session) snac0b(sub uint16, reqid uint32, data []byte) {
	if sub == 0x0002 {
		s.sendSnac(0x000B, 0x0002, []byte{0x00, 0x01}, int64(reqid), 0)
	}
}

func (s *Session) snac03(sub uint16, reqid uint32, data []byte) {
	switch sub {
	case 0x0002:
		rights := makeTLV(0x0001, beU16(0x0258))
		rights = append(rights, makeTLV(0x0002, beU16(0x02EE))...)
		rights = append(rights, makeTLV(0x0003, beU16(0x0200))...)
		s.sendSnac(0x0003, 0x0003, rights, int64(reqid), 0)
	default:
	}
}

func (s *Session) sendBuddyOnline(uin string, status uint32, caps []byte, xstatusRaw []byte) {
	if !s.isRunning() || s.uin == "" {
		return
	}
	uinB := []byte(uin)
	srcSession := s.server.getSession(uin)

	uclass := uint16(0x0050)
	if status != 0 {
		uclass |= 0x0020
	}

	var ipInt uint32
	var dcInfo []byte
	var signon uint32
	if srcSession != nil {
		ipInt = peerIPUint32(srcSession.conn)
		dcInfo = srcSession.dcInfo
		if !srcSession.loginTs.IsZero() {
			signon = uint32(srcSession.loginTs.Unix())
		}
	}
	if signon == 0 {
		signon = uint32(time.Now().Unix())
	}
	dcInfo = pad37(dcInfo)

	var tlvs []byte
	tlvCount := 0
	tlvs = append(tlvs, makeTLV(0x0001, beU16(uclass))...)
	tlvCount++
	tlvs = append(tlvs, makeTLV(0x000C, dcInfo)...)
	tlvCount++
	tlvs = append(tlvs, makeTLV(0x000A, beU32(ipInt))...)
	tlvCount++
	tlvs = append(tlvs, makeTLV(0x0006, beU32(status))...)
	tlvCount++
	if len(caps) > 0 {
		tlvs = append(tlvs, makeTLV(0x000D, caps)...)
		tlvCount++
	}
	tlvs = append(tlvs, makeTLV(0x000F, beU32(0))...)
	tlvCount++
	tlvs = append(tlvs, makeTLV(0x0003, beU32(signon))...)
	tlvCount++
	if xstatusRaw != nil {
		tlvs = append(tlvs, makeTLV(0x001D, xstatusRaw)...)
		tlvCount++
	}
	payload := make([]byte, 0)
	payload = append(payload, byte(len(uinB)))
	payload = append(payload, uinB...)
	payload = append(payload, beU16(0x0000)...)
	payload = append(payload, beU16(uint16(tlvCount))...)
	payload = append(payload, tlvs...)
	s.sendSnac(0x0003, 0x000B, payload, noReqID, 0)
}

func pad37(dc []byte) []byte {
	out := make([]byte, 37)
	copy(out, dc)
	return out
}

func peerIPUint32(conn net.Conn) uint32 {
	return ipToUint32(hostOnly(conn.RemoteAddr()))
}

func (s *Session) sendBuddyOffline(uin string) {
	if !s.isRunning() || s.uin == "" {
		return
	}

	uinB := []byte(uin)
	payload := append([]byte{byte(len(uinB))}, uinB...)
	payload = append(payload, beU16(0x0000)...)
	payload = append(payload, beU16(0x0001)...)
	payload = append(payload, makeTLV(0x0001, beU16(0x0000))...)
	s.sendSnac(0x0003, 0x000C, payload, noReqID, 0)
}

func (s *Session) notifyOthersOnline() {
	if s.uin == "" {
		return
	}
	user, err := s.server.Storage.GetUser(s.uin)
	if err != nil || user == nil {
		return
	}
	if _, ok := user.Contacts[s.uin]; ok {
		if privacyVisible(user, s.uin, true) {
			s.sendBuddyOnline(s.uin, s.status, s.caps, s.xstatusRaw)
		}
	}
	s.server.forEachSession(func(otherUin string, sess *Session) {
		if otherUin == s.uin || s.uin == "" {
			return
		}
		otherUser, err := s.server.Storage.GetUser(otherUin)
		if err != nil || otherUser == nil {
			return
		}
		if _, ok := otherUser.Contacts[s.uin]; ok {
			if privacyVisible(user, otherUin, true) && !pendingAuthHidesPresence(otherUser, s.uin) {
				sess.sendBuddyOnline(s.uin, s.status, s.caps, s.xstatusRaw)
			}
		}
	})
}

func (s *Session) sendPresenceFull() {
	if s.uin == "" {
		return
	}
	user, err := s.server.Storage.GetUser(s.uin)
	if err != nil || user == nil {
		return
	}
	if _, ok := user.Contacts[s.uin]; ok {
		if privacyVisible(user, s.uin, true) {
			s.sendBuddyOnline(s.uin, s.status, s.caps, s.xstatusRaw)
		}
	}
	s.server.forEachSession(func(otherUin string, sess *Session) {
		if otherUin == s.uin || s.uin == "" {
			return
		}
		otherUser, err := s.server.Storage.GetUser(otherUin)
		if err != nil || otherUser == nil {
			return
		}
		if _, ok := user.Contacts[otherUin]; ok {
			if privacyVisible(otherUser, s.uin, true) && !pendingAuthHidesPresence(user, otherUin) {
				s.sendBuddyOnline(otherUin, sess.status, sess.caps, sess.xstatusRaw)
			}
		}
	})
}

func (s *Session) broadcastOnline() {
	s.notifyOthersOnline()
	if s.ssiActivated {
		s.sendPresenceFull()
	}
}

func (s *Session) broadcastPresence() {
	if s.uin == "" {
		return
	}
	user, err := s.server.Storage.GetUser(s.uin)
	if err != nil || user == nil {
		return
	}
	if _, ok := user.Contacts[s.uin]; ok {
		if privacyVisible(user, s.uin, true) {
			s.sendBuddyOnline(s.uin, s.status, s.caps, s.xstatusRaw)
		}
	}
	s.server.forEachSession(func(otherUin string, sess *Session) {
		if otherUin == s.uin || s.uin == "" {
			return
		}
		otherUser, err := s.server.Storage.GetUser(otherUin)
		if err != nil || otherUser == nil {
			return
		}
		if _, ok := otherUser.Contacts[s.uin]; ok {
			if privacyVisible(user, otherUin, true) && !pendingAuthHidesPresence(otherUser, s.uin) {
				sess.sendBuddyOnline(s.uin, s.status, s.caps, s.xstatusRaw)
			}
		}
	})
}

func (s *Session) broadcastOfflineSync() {
	if s.uin == "" {
		return
	}
	user, err := s.server.Storage.GetUser(s.uin)
	if err != nil || user == nil {
		return
	}
	s.server.forEachSession(func(otherUin string, sess *Session) {
		if otherUin == s.uin || s.uin == "" {
			return
		}
		otherUser, err := s.server.Storage.GetUser(otherUin)
		if err != nil || otherUser == nil {
			return
		}
		if _, ok := otherUser.Contacts[s.uin]; ok {
			sess.sendBuddyOffline(s.uin)
		}
	})
}

func (s *Session) snac04(sub uint16, reqid uint32, data []byte) {
	switch sub {
	case 0x0004:
		payload := beU16(0x0002)
		payload = append(payload, beU32(0x00000003)...)
		payload = append(payload, beU16(0x0200)...)
		payload = append(payload, beU16(999)...)
		payload = append(payload, beU16(999)...)
		payload = append(payload, beU16(0)...)
		payload = append(payload, beU16(1000)...)
		s.sendSnac(0x0004, 0x0005, payload, int64(reqid), 0)
	case 0x0006:
		s.handleSendMessage(reqid, data)
	case 0x0002:

		if len(data) >= 6 {
			channel := getBE16(data, 0)
			icbmFlags := getBE32(data, 2)
			if channel <= MaxIcbmChannels {
				if channel == 0 {
					for ch := uint16(1); ch <= MaxIcbmChannels; ch++ {
						s.icbmFlags[ch] = icbmFlags
					}
				} else {
					s.icbmFlags[channel] = icbmFlags
				}
			}
		}
	case 0x000B:
		s.handleServerRelay(data)
	case 0x000C:
		if len(data) >= 11 {
			channel := getBE16(data, 8)
			if channel != 2 {
				s.relayGenericICBM(sub, data)
			}
		}
	case 0x0014:
		s.handleTyping(data)
	default:
		s.relayGenericICBM(sub, data)
	}
}

func (s *Session) relayGenericICBM(sub uint16, data []byte) {
	if len(data) < 11 {
		return
	}
	cookie := data[:8]
	channel := getBE16(data, 8)
	pos := 10
	uinLen := int(data[pos])
	pos++
	toUin := string(data[pos : pos+uinLen])
	pos += uinLen
	rest := data[pos:]
	if target := s.server.getSession(toUin); target != nil {
		fwd := append(append([]byte{}, cookie...), beU16(channel)...)
		fwd = append(fwd, byte(len(s.uin)))
		fwd = append(fwd, []byte(s.uin)...)
		fwd = append(fwd, rest...)
		s.spawn(func() { target.sendSnac(0x0004, sub, fwd, noReqID, 0) })
	}
}

func (s *Session) handleSendMessage(reqid uint32, data []byte) {
	if len(data) < 11 {
		s.sendSnac(0x0004, 0x0001, beU16(0x0000), int64(reqid), 0)
		return
	}
	cookie := data[:8]
	channel := getBE16(data, 8)
	pos := 10
	uinLen := int(data[pos])
	pos++
	toUin := string(data[pos : pos+uinLen])
	pos += uinLen
	tlvsData := data[pos:]

	if _, wantsAck := parseTLVs(tlvsData)[0x0003]; wantsAck {
		ack := append(append([]byte{}, cookie...), beU16(channel)...)
		ack = append(ack, byte(len(toUin)))
		ack = append(ack, []byte(toUin)...)
		s.sendSnac(0x0004, 0x000C, ack, int64(reqid), 0)
	}

	target := s.server.getSession(toUin)
	if target != nil {
		s.spawn(func() { target.deliverV7Message(s.uin, channel, cookie, tlvsData) })

		if channel == 1 && (target.icbmFlags[1]&IcbmFlgMtn) != 0 {
			uinB := []byte(s.uin)
			mtnFinish := make([]byte, 0, 8+2+1+len(uinB)+2)
			mtnFinish = append(mtnFinish, make([]byte, 8)...)
			mtnFinish = append(mtnFinish, beU16(1)...)
			mtnFinish = append(mtnFinish, byte(len(uinB)))
			mtnFinish = append(mtnFinish, uinB...)
			mtnFinish = append(mtnFinish, beU16(0)...)
			s.spawn(func() { target.sendSnac(0x0004, 0x0014, mtnFinish, noReqID, 0) })
		}
		return
	}

	if channel != 1 && channel != 4 {
		return
	}
	text := s.extractMessageText(channel, tlvsData)
	if text == "" {
		return
	}
	s.server.Storage.AddOfflineMsg(toUin, s.uin, text)
}

func (s *Session) deliverV7Message(fromUin string, channel uint16, origCookie []byte, rawTLVsData []byte) {
	buin := []byte(fromUin)
	var cookie []byte
	if channel == 1 {
		cookie = append(beU32(uint32(time.Now().Unix())), beU32(uint32(rand.Int31()))...)
	} else {
		cookie = origCookie
	}

	rawTLVsData = ensureMsgFeaturesTLV(channel, rawTLVsData)

	sender := s.server.getSession(fromUin)
	status := StatusOnline
	var uptime uint32
	if sender != nil {
		status = sender.status
		if !sender.loginTs.IsZero() {
			uptime = uint32(time.Since(sender.loginTs).Seconds())
		}
	}

	presence := makeTLV(0x0001, beU16(0))
	presence = append(presence, makeTLV(0x0006, append(beU16(0), beU16(uint16(status&0xFFFF))...))...)
	presence = append(presence, makeTLV(0x000F, beU32(uptime))...)
	presence = append(presence, makeTLV(0x0003, beU32(0))...)

	payload := append([]byte{}, cookie...)
	payload = append(payload, beU16(channel)...)
	payload = append(payload, byte(len(buin)))
	payload = append(payload, buin...)
	payload = append(payload, beU16(0x0000)...)
	payload = append(payload, beU16(4)...)
	payload = append(payload, presence...)
	payload = append(payload, rawTLVsData...)

	s.sendSnac(0x0004, 0x0007, payload, noReqID, 0)
}

func (s *Session) handleServerRelay(data []byte) {
	if len(data) < 11 {
		return
	}
	cookie := data[:8]
	channel := getBE16(data, 8)
	pos := 10
	uinLen := int(data[pos])
	pos++
	toUin := string(data[pos : pos+uinLen])
	pos += uinLen
	tlvsData := data[pos:]

	if target := s.server.getSession(toUin); target != nil {
		fwd := append(append([]byte{}, cookie...), beU16(channel)...)
		fwd = append(fwd, byte(len(s.uin)))
		fwd = append(fwd, []byte(s.uin)...)
		fwd = append(fwd, tlvsData...)
		s.spawn(func() { target.sendSnac(0x0004, 0x000B, fwd, noReqID, 0) })
	}
}

func (s *Session) handleTyping(data []byte) {
	if len(data) < 11 {
		return
	}
	channel := getBE16(data, 8)
	if channel == 0 || channel > MaxIcbmChannels {
		return
	}
	pos := 10
	uinLen := int(data[pos])
	pos++
	toUin := string(data[pos : pos+uinLen])
	pos += uinLen
	var mtnType uint16
	if pos+2 <= len(data) {
		mtnType = getBE16(data, pos)
	}
	if mtnType > 2 {
		mtnType = 0
	}
	target := s.server.getSession(toUin)
	if target == nil {
		return
	}
	if target.icbmFlags[channel]&IcbmFlgMtn == 0 {
		return
	}
	fwd := make([]byte, 0, 8+2+1+len(s.uin)+2)
	fwd = append(fwd, make([]byte, 8)...)
	fwd = append(fwd, beU16(channel)...)
	fwd = append(fwd, byte(len(s.uin)))
	fwd = append(fwd, []byte(s.uin)...)
	fwd = append(fwd, beU16(mtnType)...)
	s.spawn(func() { target.sendSnac(0x0004, 0x0014, fwd, noReqID, 0) })
}

func (s *Session) extractMessageText(channel uint16, tlvsData []byte) string {
	defer func() { recover() }()
	tlvs := parseTLVs(tlvsData)
	if channel == 1 {
		raw2, ok := tlvs[0x0002]
		if !ok || len(raw2) < 4 {
			return ""
		}
		inner := parseTLVs(raw2)
		rawText, ok := inner[0x0101]
		if !ok || len(rawText) < 4 {
			return ""
		}
		charset := getBE16(rawText, 0)
		textData := rawText[4:]
		if charset == 2 {
			return decodeUTF16BE(textData)
		}
		return decodeMessageText(textData)
	} else if channel == 2 {
		raw5, ok := tlvs[0x0005]
		if !ok || len(raw5) < 26 {
			return ""
		}
		inner := parseTLVs(raw5[26:])
		raw2711, ok := inner[0x2711]
		if !ok || len(raw2711) < 36 {
			return ""
		}
		p := 36
		for p+4 <= len(raw2711) {
			t := getLE16(raw2711, p)
			l := int(getLE16(raw2711, p+2))
			if p+4+l > len(raw2711) {
				break
			}
			if (t == 0x0001 || t == 0x0021) && l > 0 {
				text := raw2711[p+4 : p+4+l]
				return decodeMessageText(text)
			}
			p += 4 + l
		}
	} else if channel == 4 {
		raw5, ok := tlvs[0x0005]
		if !ok || len(raw5) < 8 {
			return ""
		}
		strLen := int(getLE16(raw5, 6))
		if 8+strLen > len(raw5) {
			strLen = len(raw5) - 8
		}
		if strLen <= 0 {
			return ""
		}
		strBytes := raw5[8 : 8+strLen]
		strBytes = bytesTrimRightNull(strBytes)
		return decodeMessageText(strBytes)
	}
	return ""
}

func bytesTrimRightNull(b []byte) []byte {
	for len(b) > 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	return b
}

func tryUTF8(b []byte) (string, bool) {
	if utf8.Valid(b) {
		return trimNul(string(b)), true
	}
	return "", false
}

func trimNul(s string) string {
	for len(s) > 0 && s[len(s)-1] == 0 {
		s = s[:len(s)-1]
	}
	for len(s) > 0 && s[0] == 0 {
		s = s[1:]
	}
	return s
}

func decodeUTF16BE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u16 = append(u16, binary.BigEndian.Uint16(b[i:]))
	}
	runes := utf16.Decode(u16)
	return trimNul(string(runes))
}
