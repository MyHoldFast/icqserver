package main

import (
	"strconv"
	"strings"
	"time"
)

func (s *Session) snac15(sub uint16, reqid uint32, data []byte) {
	if sub != 0x0002 {
		return
	}
	if len(data) < 6 {
		return
	}
	tlvType := getBE16(data, 0)
	tlvLen := int(getBE16(data, 2))
	if tlvType != 0x0001 || 4+tlvLen > len(data) {
		return
	}
	tlvValue := data[4 : 4+tlvLen]
	if len(tlvValue) < 2 {
		return
	}
	body := tlvValue[2:]
	if len(body) < 6 {
		return
	}
	uinInt := getLE32(body, 0)
	markerOrCmd := getLE16(body, 4)

	if markerOrCmd == MetaReqOfflineMsg || markerOrCmd == MetaAckOfflineMsg {
		if markerOrCmd == MetaReqOfflineMsg {
			var reqSeq uint16
			if len(body) >= 8 {
				reqSeq = getLE16(body, 6)
			}
			s.handleMetaReqOffline(uinInt, reqSeq, reqid)
		} else {
			s.handleMetaAckOffline()
		}
		return
	}

	if len(body) < 10 {
		return
	}
	seqID := getLE16(body, 6)
	subtype := getLE16(body, 8)
	payload := body[10:]

	switch subtype {
	case CliMetaReqMoreInfoType, CliMetaReqHomeInfoType:
		s.handleMetaRequestInfo(uinInt, seqID, payload, reqid)
	case CliMetaReqShortInfoType:
		s.handleMetaRequestShortInfo(uinInt, seqID, payload, reqid)
	case CliSetFullInfoType:
		s.handleMetaSaveInfo(uinInt, seqID, payload, reqid)
	case 0x055F:
		s.handleMetaSearch(uinInt, seqID, payload, reqid)
	case 0x0569:
		s.handleMetaSearchByUin2(uinInt, seqID, payload, reqid)
	case 0x0FA0:
		s.handleMetaSearchUTF8(uinInt, seqID, payload, reqid)
	case MetaInfoSetPassword:
		s.handleMetaSetPassword(uinInt, seqID, payload, reqid)
	case MetaInfoSetPerms:
		s.handleMetaSetPerms(uinInt, seqID, payload, reqid)
	case CliMetaSrvxmlReq:
		s.handleMetaServiceConfig(uinInt, seqID, payload, reqid)
	default:
	}
}

func (s *Session) makeMetaReply(uin uint32, seqID uint16, subtype uint16, success byte, data []byte) []byte {
	inner := append(leU32(uin), leU16(0x07DA)...)
	inner = append(inner, leU16(seqID)...)
	inner = append(inner, leU16(subtype)...)
	inner = append(inner, success)
	inner = append(inner, data...)
	tlvBody := append(leU16(uint16(len(inner))), inner...)
	return makeTLV(0x0001, tlvBody)
}

func (s *Session) makeMetaReplyOffline(uin uint32, subtype uint16, seqID uint16, payload []byte) []byte {
	inner := append(leU32(uin), leU16(subtype)...)
	inner = append(inner, leU16(seqID)...)
	inner = append(inner, payload...)
	tlvBody := append(leU16(uint16(len(inner))), inner...)
	return makeTLV(0x0001, tlvBody)
}

func (s *Session) handleMetaRequestInfo(uinInt uint32, seqID uint16, payload []byte, reqid uint32) {
	if len(payload) < 4 {
		return
	}
	targetUin := strconv.FormatUint(uint64(getLE32(payload, 0)), 10)
	user, _ := s.server.Storage.GetUser(targetUin)
	var prof UserProfile
	if user != nil {
		prof = user.Profile
	}

	var body []byte
	for _, f := range []string{prof.Nick, prof.FirstName, prof.LastName, prof.Email, prof.City,
		prof.State, prof.Phone, prof.Fax, prof.Address, prof.CellPhone} {
		body = append(body, makeAsciizLEIcq(f)...)
	}
	body = append(body, makeAsciizLEIcq("")...)
	body = append(body, leU16(0)...)
	body = append(body, 0)
	authByte := byte(1)
	if prof.AuthRequired {
		authByte = 0
	}
	body = append(body, authByte, 0, 0, 1)
	reply := s.makeMetaReply(uinInt, seqID, SrvMetaGeneralType, 0x0A, body)
	s.sendSnac(0x0015, 0x0003, reply, int64(reqid), 1)

	var body2 []byte
	body2 = append(body2, leU16(prof.Age)...)
	genderMap := map[string]byte{"F": 1, "M": 2}
	body2 = append(body2, genderMap[strings.ToUpper(prof.Gender)])
	body2 = append(body2, makeAsciizLEIcq(prof.HomePage)...)
	if prof.Birthday != "" {
		parts := strings.Split(prof.Birthday, ".")
		if len(parts) == 3 {
			d, e1 := strconv.Atoi(parts[0])
			m, e2 := strconv.Atoi(parts[1])
			y, e3 := strconv.Atoi(parts[2])
			if e1 == nil && e2 == nil && e3 == nil {
				body2 = append(body2, leU16(uint16(y))...)
				body2 = append(body2, byte(m), byte(d))
			} else {
				body2 = append(body2, leU16(0)...)
				body2 = append(body2, 0, 0)
			}
		} else {
			body2 = append(body2, leU16(0)...)
			body2 = append(body2, 0, 0)
		}
	} else {
		body2 = append(body2, leU16(0)...)
		body2 = append(body2, 0, 0)
	}
	body2 = append(body2, 0, 0, 0)
	body2 = append(body2, leU16(0)...)
	body2 = append(body2, leU16(1)...)
	body2 = append(body2, 0)
	body2 = append(body2, leU16(1)...)
	body2 = append(body2, 0)
	body2 = append(body2, leU16(0)...)
	body2 = append(body2, 0)
	reply2 := s.makeMetaReply(uinInt, seqID, SrvMetaMoreType, 0x0A, body2)
	s.sendSnac(0x0015, 0x0003, reply2, int64(reqid), 1)

	bodyEmail := []byte{0}
	replyEmail := s.makeMetaReply(uinInt, seqID, MetaInfoEmailMore, 0x0A, bodyEmail)
	s.sendSnac(0x0015, 0x0003, replyEmail, int64(reqid), 1)

	bodyHpage := append([]byte{0}, leU16(0)...)
	bodyHpage = append(bodyHpage, makeAsciizLEIcq("")...)
	bodyHpage = append(bodyHpage, 0)
	replyHpage := s.makeMetaReply(uinInt, seqID, MetaInfoHpageCat, 0x0A, bodyHpage)
	s.sendSnac(0x0015, 0x0003, replyHpage, int64(reqid), 1)

	var body3 []byte
	for _, f := range []string{prof.WorkCity, prof.WorkState, prof.WorkPhone, prof.WorkFax, prof.WorkAddr} {
		body3 = append(body3, makeAsciizLEIcq(f)...)
	}
	body3 = append(body3, makeAsciizLEIcq("")...)
	body3 = append(body3, leU16(0)...)
	body3 = append(body3, makeAsciizLEIcq(prof.WorkName)...)
	body3 = append(body3, makeAsciizLEIcq(prof.WorkDep)...)
	body3 = append(body3, makeAsciizLEIcq(prof.WorkPos)...)
	body3 = append(body3, leU16(0)...)
	body3 = append(body3, makeAsciizLEIcq("")...)
	reply3 := s.makeMetaReply(uinInt, seqID, SrvMetaWorkType, 0x0A, body3)
	s.sendSnac(0x0015, 0x0003, reply3, int64(reqid), 1)

	body4 := makeAsciizLEIcq(prof.About)
	reply4 := s.makeMetaReply(uinInt, seqID, SrvMetaAboutType, 0x0A, body4)
	s.sendSnac(0x0015, 0x0003, reply4, int64(reqid), 1)

	bodyInt := []byte{0}
	for i := 0; i < 4; i++ {
		bodyInt = append(bodyInt, leU16(0)...)
		bodyInt = append(bodyInt, makeAsciizLEIcq("")...)
	}
	replyInt := s.makeMetaReply(uinInt, seqID, MetaInfoInterests, 0x0A, bodyInt)
	s.sendSnac(0x0015, 0x0003, replyInt, int64(reqid), 1)

	bodyAff := []byte{0x03}
	for i := 0; i < 3; i++ {
		bodyAff = append(bodyAff, leU16(0)...)
		bodyAff = append(bodyAff, makeAsciizLEIcq("")...)
	}
	bodyAff = append(bodyAff, 0x03)
	for i := 0; i < 3; i++ {
		bodyAff = append(bodyAff, leU16(0)...)
		bodyAff = append(bodyAff, makeAsciizLEIcq("")...)
	}
	bodyAff = append(bodyAff, leU16(0)...)
	bodyAff = append(bodyAff, leU16(1)...)
	bodyAff = append(bodyAff, 0)
	replyAff := s.makeMetaReply(uinInt, seqID, MetaInfoAffilations, 0x0A, bodyAff)
	s.sendSnac(0x0015, 0x0003, replyAff, int64(reqid), 0)
}

func (s *Session) handleMetaRequestShortInfo(uinInt uint32, seqID uint16, payload []byte, reqid uint32) {
	if len(payload) < 4 {
		return
	}
	targetUin := strconv.FormatUint(uint64(getLE32(payload, 0)), 10)
	user, _ := s.server.Storage.GetUser(targetUin)
	if user == nil {
		reply := s.makeMetaReply(uinInt, seqID, MetaInfoShort, MetaFail, nil)
		s.sendSnac(0x0015, 0x0003, reply, int64(reqid), 0)
		return
	}
	prof := user.Profile
	var body []byte
	body = append(body, makeAsciizLEIcq(prof.Nick)...)
	body = append(body, makeAsciizLEIcq(prof.FirstName)...)
	body = append(body, makeAsciizLEIcq(prof.LastName)...)
	body = append(body, makeAsciizLEIcq(prof.Email)...)
	authByte := byte(1)
	if prof.AuthRequired {
		authByte = 0
	}
	genderMap := map[string]byte{"F": 1, "M": 2}
	body = append(body, authByte, 0, genderMap[strings.ToUpper(prof.Gender)])
	reply := s.makeMetaReply(uinInt, seqID, MetaInfoShort, MetaSuccess, body)
	s.sendSnac(0x0015, 0x0003, reply, int64(reqid), 0)
}

func (s *Session) handleMetaSaveInfo(uinInt uint32, seqID uint16, payload []byte, reqid uint32) {
	user, err := s.server.Storage.GetUser(s.uin)
	if err != nil || user == nil {
		return
	}
	prof := &user.Profile
	pos := 0
	var authTlvSeen bool
	var authTlvValue byte
	var auth2TlvSeen bool
	var auth2TlvValue byte

	for pos+4 <= len(payload) {
		tlvID := getLE16(payload, pos)
		tlvLen := int(getLE16(payload, pos+2))
		pos += 4
		if pos+tlvLen > len(payload) {
			break
		}
		tlvData := payload[pos : pos+tlvLen]
		pos += tlvLen

		switch tlvID {
		case SaveTlvNick, SaveTlvFirstName, SaveTlvLastName, SaveTlvHomePage, SaveTlvAbout, SaveTlvCity:
			if len(tlvData) >= 2 {
				innerLen := int(getLE16(tlvData, 0))
				end := 2 + innerLen
				if end > len(tlvData) {
					end = len(tlvData)
				}
				raw := trimTrailingNul(tlvData[2:end])
				text := decodeCP1251(raw)
				if tlvID == SaveTlvHomePage {
					text = validateHomepage(text)
				} else {
					text = validateProfileText(text, 255)
				}
				switch tlvID {
				case SaveTlvNick:
					prof.Nick = text
				case SaveTlvFirstName:
					prof.FirstName = text
				case SaveTlvLastName:
					prof.LastName = text
				case SaveTlvHomePage:
					prof.HomePage = text
				case SaveTlvAbout:
					prof.About = text
				case SaveTlvCity:
					prof.City = text
				}
			}
		case SaveTlvEmail:
			if len(tlvData) >= 3 {
				innerLen := int(getLE16(tlvData, 0))
				end := 2 + innerLen
				if end > len(tlvData) {
					end = len(tlvData)
				}
				raw := trimTrailingNul(tlvData[2:end])
				var flag byte
				if end < len(tlvData) {
					flag = tlvData[end]
				}
				if len(raw) > 0 && flag != 0x01 {
					prof.Email = validateEmail(string(raw))
				}
			}
		case SaveTlvBday:
			if len(tlvData) >= 6 {
				year := getLE16(tlvData, 0)
				mon := getLE16(tlvData, 2)
				day := getLE16(tlvData, 4)
				prof.Birthday = validateBirthday(int(day), int(mon), int(year))
			}
		case SaveTlvGender:
			if len(tlvData) >= 1 {
				g := tlvData[0]
				switch g {
				case 1:
					prof.Gender = "F"
				case 2:
					prof.Gender = "M"
				default:
					prof.Gender = ""
				}
			}
		case SaveTlvAuth:
			if len(tlvData) >= 1 {
				authTlvSeen = true
				authTlvValue = tlvData[0]
			}
		case SaveTlvAuth2:
			if len(tlvData) >= 1 {
				auth2TlvSeen = true
				auth2TlvValue = tlvData[0]
			}
		}
	}

	if auth2TlvSeen && auth2TlvValue == 1 {
		prof.AuthRequired = false
	} else if authTlvSeen {
		prof.AuthRequired = (authTlvValue != 1)
	} else {
		prof.AuthRequired = false
	}

	s.server.Storage.SaveProfile(s.uin, *prof)
	ack := s.makeMetaReply(uinInt, seqID, 0x0C3F, 0x0A, nil)
	s.sendSnac(0x0015, 0x0003, ack, int64(reqid), 0)
}

func trimTrailingNul(b []byte) []byte {
	for len(b) > 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	return b
}

func (s *Session) handleMetaSearch(uinInt uint32, seqID uint16, payload []byte, reqid uint32) {
	c := SearchCriteria{}
	pos := 0
	for pos+4 <= len(payload) {
		t := getLE16(payload, pos)
		outerLen := int(getLE16(payload, pos+2))
		pos += 4
		if pos+outerLen > len(payload) {
			break
		}
		block := payload[pos : pos+outerLen]
		pos += outerLen

		switch {
		case t == SearchTlvUin && len(block) >= 4:
			c.UIN = strconv.FormatUint(uint64(getLE32(block, 0)), 10)
		case (t == SearchTlvNick || t == SearchTlvFirstName || t == SearchTlvLastName ||
			t == SearchTlvEmail || t == SearchTlvCity) && len(block) >= 2:
			innerLen := int(getLE16(block, 0))
			end := 2 + innerLen
			if end > len(block) {
				end = len(block)
			}
			raw := trimTrailingNul(block[2:end])
			text := decodeCP1251(raw)
			switch t {
			case SearchTlvNick:
				c.Nick = text
			case SearchTlvFirstName:
				c.FirstName = text
			case SearchTlvLastName:
				c.LastName = text
			case SearchTlvEmail:
				c.Email = text
			case SearchTlvCity:
				c.City = text
			}
		case t == SearchTlvOnlyOnline && len(block) >= 1:
			c.OnlyOnline = block[0] != 0
		}
	}

	online := s.onlineUinSet()
	results := s.server.Storage.SearchUsers(c, online)
	if c.UIN != "" {
		filtered := results[:0]
		for _, r := range results {
			if r.UIN == c.UIN {
				filtered = append(filtered, r)
			}
		}
		results = filtered
	}

	n := len(results)
	if n == 0 {
		s.sendWpFound(uinInt, seqID, reqid, nil, false, 0, true, 0)
		return
	}
	for i, r := range results {
		isLast := i == n-1
		rc := r
		s.sendWpFound(uinInt, seqID, reqid, &rc, true, 1, isLast, 0)
	}
}

func (s *Session) onlineUinSet() map[string]bool {
	online := map[string]bool{}
	s.server.forEachSession(func(uin string, _ *Session) { online[uin] = true })
	return online
}

func (s *Session) handleMetaSearchByUin2(uinInt uint32, seqID uint16, payload []byte, reqid uint32) {
	var targetUin uint32
	found := false
	pos := 0
	for pos+4 <= len(payload) {
		t := getLE16(payload, pos)
		ln := int(getLE16(payload, pos+2))
		pos += 4
		avail := len(payload) - pos
		take := ln
		if take > avail {
			take = avail
		}
		block := payload[pos : pos+take]
		pos += take
		if t == 0x0136 && len(block) >= 4 {
			targetUin = getLE32(block, len(block)-4)
			found = true
		}
	}
	if !found {
		return
	}
	targetStr := strconv.FormatUint(uint64(targetUin), 10)
	online := s.onlineUinSet()
	results := s.server.Storage.SearchUsers(SearchCriteria{UIN: targetStr}, online)
	var match *SearchResult
	for _, r := range results {
		if r.UIN == targetStr {
			rc := r
			match = &rc
			break
		}
	}
	if match != nil {

		s.sendWpFound(uinInt, seqID, reqid, match, true, 0, true, 0)
	} else {
		s.sendWpFound(uinInt, seqID, reqid, nil, false, 0, true, 0)
	}
}

func (s *Session) handleMetaSearchUTF8(uinInt uint32, seqID uint16, payload []byte, reqid uint32) {
	const fixedPreamble = 2 + 2 + 2 + 16
	if len(payload) < fixedPreamble+2+2+2 {
		return
	}
	critLen := int(getBE16(payload, fixedPreamble+4))
	start := fixedPreamble + 6
	end := start + critLen
	if end > len(payload) {
		end = len(payload)
	}
	critBytes := payload[start:end]

	fieldMap := map[uint16]*string{}
	c := SearchCriteria{}
	fieldMap[120] = &c.Nick
	fieldMap[100] = &c.FirstName
	fieldMap[110] = &c.LastName
	fieldMap[160] = &c.City

	pos := 0
	for pos+4 <= len(critBytes) {
		t := getBE16(critBytes, pos)
		ln := int(getBE16(critBytes, pos+2))
		pos += 4
		if pos+ln > len(critBytes) {
			break
		}
		val := critBytes[pos : pos+ln]
		pos += ln
		if fp, ok := fieldMap[t]; ok {
			*fp = string(val)
		}
	}

	online := s.onlineUinSet()
	results := s.server.Storage.SearchUsers(c, online)
	s.sendSearchResultsUTF8(uinInt, seqID, results, reqid)
}

func (s *Session) sendWpFound(uinInt uint32, seqID uint16, reqid uint32, r *SearchResult,
	success bool, snacFlags uint16, isLast bool, usersLeft uint32) {

	marker := uint16(SrvSearchFound)
	if isLast {
		marker = SrvSearchLast
	}
	if !success || r == nil {
		reply := s.makeMetaReply(uinInt, seqID, marker, MetaEmpty, nil)
		s.sendSnac(0x0015, 0x0003, reply, int64(reqid), int64ToU16(snacFlags))
		return
	}

	cp1251Len := func(str string) int { return len(encodeCP1251(str)) }

	uinN, _ := strconv.ParseUint(r.UIN, 10, 32)
	var data []byte
	data = append(data, leU32(uint32(uinN))...)
	data = append(data, makeAsciizLEIcq(r.Nick)...)
	data = append(data, makeAsciizLEIcq(r.FirstName)...)
	data = append(data, makeAsciizLEIcq(r.LastName)...)
	data = append(data, makeAsciizLEIcq(r.Email)...)
	authByte := byte(1)
	if r.AuthReq {
		authByte = 0
	}
	data = append(data, authByte, 0x02, 0)
	genderMap := map[string]byte{"F": 1, "M": 2}
	data = append(data, genderMap[strings.ToUpper(r.Gender)])
	age := r.Age
	if age > 255 {
		age = 255
	}
	data = append(data, byte(age), 0)
	if isLast {
		data = append(data, leU32(usersLeft)...)
	}
	data = append(data, leU16(0)...)

	packLen := 8 + 4 + 3 + 3 + 2
	if isLast {
		packLen += 4
	}
	packLen += cp1251Len(r.Nick) + cp1251Len(r.FirstName) + cp1251Len(r.LastName) + cp1251Len(r.Email)

	reply := s.makeMetaReply(uinInt, seqID, marker, MetaSuccess, append(leU16(uint16(packLen)), data...))
	s.sendSnac(0x0015, 0x0003, reply, int64(reqid), int64ToU16(snacFlags))
}

func int64ToU16(v uint16) uint16 { return v }

func (s *Session) sendSearchResultsUTF8(uinInt uint32, seqID uint16, results []SearchResult, reqid uint32) {
	n := len(results)
	if n == 0 {
		data := append(make([]byte, 25), beU16(0)...)
		reply := s.makeMetaReply(uinInt, seqID, MetaInfoSearchResp, MetaSuccess, data)
		s.sendSnac(0x0015, 0x0003, reply, int64(reqid), 0)
		return
	}
	genderMap := map[string]byte{"F": 1, "M": 2}
	for i, r := range results {
		isLast := i == n-1
		var tlvs []byte
		tlvs = append(tlvs, makeTLV(0x0032, []byte(r.UIN))...)
		var onlineStatus uint16
		if r.Online {
			onlineStatus = 1
		}
		tlvs = append(tlvs, makeTLV(0x0190, beU16(onlineStatus))...)
		var authTlv uint16 = 1
		if r.AuthReq {
			authTlv = 0
		}
		tlvs = append(tlvs, makeTLV(0x019A, beU16(authTlv))...)
		tlvs = append(tlvs, makeTLV(0x0078, trimTrailingNul(makeAsciizLEIcq(r.Nick)))...)
		tlvs = append(tlvs, makeTLV(0x0064, trimTrailingNul(makeAsciizLEIcq(r.FirstName)))...)
		tlvs = append(tlvs, makeTLV(0x006E, trimTrailingNul(makeAsciizLEIcq(r.LastName)))...)
		tlvs = append(tlvs, makeTLV(0x0082, []byte{genderMap[strings.ToUpper(r.Gender)]})...)
		tlvs = append(tlvs, makeTLV(0x0154, beU16(uint16(r.Age)))...)

		data := append(make([]byte, 25), beU16(uint16(n))...)
		data = append(data, beU16(1)...)
		data = append(data, make([]byte, 4)...)
		data = append(data, tlvs...)

		reply := s.makeMetaReply(uinInt, seqID, MetaInfoSearchResp, MetaSuccess, data)
		var flags uint16
		if !isLast {
			flags = 1
		}
		s.sendSnac(0x0015, 0x0003, reply, int64(reqid), int64ToU16(flags))
	}
}

func (s *Session) handleMetaReqOffline(uinInt uint32, seqID uint16, reqid uint32) {
	if s.offlineDelivered {
		eofReply := s.makeMetaReplyOffline(uinInt, OfflineMsgEOF, seqID, []byte{0})
		s.sendSnac(0x0015, 0x0003, eofReply, int64(reqid), 0)
		return
	}
	msgs := s.server.Storage.GetOfflineMsgs(s.uin)
	for _, msg := range msgs {
		var body []byte
		fromN, _ := strconv.ParseUint(msg.FromUIN, 10, 32)
		body = append(body, leU32(uint32(fromN))...)
		tm := time.Unix(int64(msg.Timestamp), 0).UTC()
		body = append(body, leU16(uint16(tm.Year()))...)
		body = append(body, byte(tm.Month()), byte(tm.Day()), byte(tm.Hour()), byte(tm.Minute()))
		body = append(body, leU16(msg.MsgType)...)

		textB := append(encodeCP1251(msg.Text), 0)
		body = append(body, leU16(uint16(len(textB)))...)
		body = append(body, textB...)

		reply := s.makeMetaReplyOffline(uinInt, OfflineMsgResponse, seqID, body)
		s.sendSnac(0x0015, 0x0003, reply, int64(reqid), 1)
	}
	eofReply := s.makeMetaReplyOffline(uinInt, OfflineMsgEOF, seqID, []byte{0})
	s.sendSnac(0x0015, 0x0003, eofReply, int64(reqid), 0)
	s.offlineDelivered = true
}

func (s *Session) handleMetaAckOffline() {
	s.server.Storage.ClearOfflineMsgs(s.uin)
}

func (s *Session) handleMetaSetPassword(uinInt uint32, seqID uint16, payload []byte, reqid uint32) {
	if len(payload) < 2 {
		return
	}
	pwLen := int(getLE16(payload, 0))
	end := 2 + pwLen
	if end > len(payload) {
		end = len(payload)
	}
	raw := trimTrailingNul(payload[2:end])
	s.server.Storage.SetPassword(s.uin, string(raw))
	ack := s.makeMetaReply(uinInt, seqID, MetaInfoPassAck, 0x0A, nil)
	s.sendSnac(0x0015, 0x0003, ack, int64(reqid), 0)
}

func (s *Session) handleMetaSetPerms(uinInt uint32, seqID uint16, payload []byte, reqid uint32) {
	if len(payload) < 1 {
		return
	}
	authByte := payload[0]
	s.server.Storage.SetAuthRequired(s.uin, authByte == 0)
	ack := s.makeMetaReply(uinInt, seqID, MetaInfoPermsAck, 0x0A, nil)
	s.sendSnac(0x0015, 0x0003, ack, int64(reqid), 0)
}

func (s *Session) handleMetaServiceConfig(uinInt uint32, seqID uint16, payload []byte, reqid uint32) {
	key := ""
	if len(payload) >= 2 {
		klen := int(getLE16(payload, 0))
		end := 2 + klen
		if end > len(payload) {
			end = len(payload)
		}
		raw := payload[2:end]
		if idx := indexByte(raw, 0); idx >= 0 {
			raw = raw[:idx]
		}
		key = string(raw)
	}
	name := key
	lo := strings.ToLower(key)
	if strings.Contains(lo, "<key>") && strings.Contains(lo, "</key>") {
		a := strings.Index(lo, "<key>") + 5
		b := strings.Index(lo, "</key>")
		if b > a {
			name = key[a:b]
		}
	}

	defaults := map[string]string{
		"cbHostIP":              "205.188.250.25",
		"BannersURL":            "http://205.188.250.25/cb/%d/datafiles/banners.cb?%s",
		"PartnersURL":           "http://205.188.250.25/cb/%d/datafiles/%s.cb",
		"ReadersURL":            "http://205.188.250.25/cb/%d/datafiles/%s.cb",
		"CLBannersURL":          "http://205.188.250.25/cb/%d/datafiles/clbanner.cb?%s",
		"DomainsURL":            "http://205.188.250.25/cb/%d/datafiles/domains.cb?%s",
		"LicenseKeysURL":        "http://cb.icq.com/cb/%d/datafiles/licensekeys.cb?%s",
		"ShowMOTDOnFirstTime":   "0",
		"ReportToICQ":           "false",
		"adsHostIP":             "ar.atwola.com",
		"ICQProDisplayBanner":   "NO",
		"ICQProDisplayCLBanner": "NO",
		"ActiveInternetTime":    "NO",
		"ActiveSMSFollowMe":     "NO",

		"BannersIdlTimeLimit":    "1000",
		"EnableSpamReport":       "NO",
		"GeoTargetCacheInterval": "1000",
		"GeoTargetURL":           "http://xtraz.icq.com/xtraz/srv/gt/gt.php",
		"GeoTargetValue":         "1",
		"LiteBannersActive":      "NO",
		"LiteCLBannerActive":     "NO",
		"NewICQPro":              "NO",
		"SkinsLinkVisible":       "NO",
		"LiteInterOpActive":      "NO",
	}

	var data []byte
	var success byte
	if val, ok := defaults[name]; ok {
		xml := append([]byte("<value>"+val+"</value>"), 0)
		data = append(leU16(uint16(len(xml))), xml...)
		success = MetaSuccess
	} else {
		data = nil
		success = MetaFail
	}
	reply := s.makeMetaReply(uinInt, seqID, SrvMetaSrvxmlRsp, success, data)
	s.sendSnac(0x0015, 0x0003, reply, int64(reqid), 0)
}

func indexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}
