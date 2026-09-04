package main

import (
	"sort"
	"time"
)

type presencePush struct {
	uin    string
	online bool
	status uint32
	caps   []byte
	xstat  []byte
}

func (s *Session) snac13(sub uint16, reqid uint32, data []byte) {
	switch sub {
	case 0x0002:

		typeLimits := []uint16{
			0x0258, 0x003D, 0x00C8, 0x00C8, 0x0001, 0x0001,
			0x0032, 0x0000, 0x0000, 0x0003, 0x0000, 0x0000,
			0x0000, 0x0080, 0x0080, 0x0014, 0x00C8, 0x0001,
			0x0000, 0x0001, 0x0000, 0x0001, 0x0028, 0x0000,
			0x0000, 0x0000,
		}
		var tlBytes []byte
		for _, v := range typeLimits {
			tlBytes = append(tlBytes, beU16(v)...)
		}
		rights := makeTLV(0x0004, tlBytes)
		rights = append(rights, makeTLV(0x0002, beU16(0x00FE))...)
		rights = append(rights, makeTLV(0x0003, beU16(0x01FC))...)
		rights = append(rights, makeTLV(0x0005, beU16(0x0064))...)
		rights = append(rights, makeTLV(0x0006, beU16(0x0061))...)
		rights = append(rights, makeTLV(0x0007, beU16(0x0000))...)
		rights = append(rights, makeTLV(0x0008, beU16(0x0000))...)
		rights = append(rights, makeTLV(0x0009, beU32(0x00069780))...)
		rights = append(rights, makeTLV(0x000A, beU32(0x0000000E))...)
		s.sendSnac(0x0013, 0x0003, rights, int64(reqid), 0)
	case 0x0004:
		s.sendRosterOrDefer(reqid)
	case 0x0005:
		s.handleSsiCheckout(data, reqid)
	case 0x0007:

		s.ssiActivated = true
		s.sendPresenceFull()
	case CliRosterAddCmd:
		s.parseAndModifySSI(data, reqid, true, false, false)
	case CliRosterUpdateCmd:
		s.parseAndModifySSI(data, reqid, false, true, false)
	case CliRosterDeleteCmd:
		s.parseAndModifySSI(data, reqid, false, false, true)
	case CliAddStartCmd:
	case CliAddEndCmd:
	case SsiAuthSendReq:
		s.handleAuthSendReq(data)
	case SsiAuthSendReply:
		s.handleAuthSendReply(data)
	case SsiDelYourself:
		s.handleDeleteYourself(data)
	default:
	}
}

func (s *Session) handleSsiCheckout(data []byte, reqid uint32) {
	s.server.Storage.EnsureDefaultGroups(s.uin)
	s.server.Storage.FixOrphanContacts(s.uin)
	var cModDate uint32
	var cItemNum uint16
	if len(data) >= 6 {
		cModDate = getBE32(data, 0)
		cItemNum = getBE16(data, 4)
	}
	modDate, itemNum := s.server.Storage.GetSsiModInfo(s.uin)
	if modDate != 0 && modDate == cModDate && itemNum == cItemNum {
		s.sendRosterUpToDate(int64(reqid), modDate, itemNum)
	} else if s.rosterSent && modDate != 0 {

		s.sendRosterUpToDate(int64(reqid), modDate, itemNum)
	} else {
		s.sendRosterOrDefer(reqid)
	}
}

func (s *Session) sendRosterOrDefer(reqid uint32) {

	s.sendRoster(int64(reqid))
}

func (s *Session) sendRoster(reqid int64) {
	s.server.Storage.EnsureDefaultGroups(s.uin)
	s.server.Storage.FixOrphanContacts(s.uin)
	modDate, itemCount := s.server.Storage.GetSsiModInfo(s.uin)
	user, err := s.server.Storage.GetUser(s.uin)
	if err != nil || user == nil {
		return
	}
	udate := modDate
	if udate == 0 {
		udate = uint32(time.Now().Unix())
	}
	ssiData := buildSSIData(user.GroupOrder, user.Groups, user.Contacts, user.Permit, user.Deny, user.PDMode, udate, user.MiscItems)
	if len(ssiData) >= 3 {
		realCount := getBE16(ssiData, 1)
		if modDate == 0 {
			s.server.Storage.SetSsiModInfo(s.uin, udate, realCount)
			itemCount = realCount
		} else if realCount != itemCount {
			s.server.Storage.SetSsiModInfo(s.uin, modDate, realCount)
			itemCount = realCount
		}
	}
	_ = itemCount
	s.sendSnac(0x0013, 0x0006, ssiData, reqid, 0)
	s.rosterSent = true
}

func (s *Session) sendRosterUpToDate(reqid int64, modDate uint32, itemNum uint16) {
	if modDate == 0 && itemNum == 0 {
		modDate, itemNum = s.server.Storage.GetSsiModInfo(s.uin)
	}
	payload := append(beU32(modDate), beU16(itemNum)...)
	s.sendSnac(0x0013, 0x000F, payload, reqid, 0)
}

func (s *Session) sendSSIAck(result int, reqid uint32) {
	s.sendSnac(0x0013, SrvUpdateAckCmd, beU16(uint16(result)), int64(reqid), 0)
}

func (s *Session) parseAndModifySSI(data []byte, reqid uint32, isAdd, isUpdate, isDelete bool) {
	user, err := s.server.Storage.GetUser(s.uin)
	if err != nil || user == nil {
		s.sendSSIAck(SsiUpdateError, reqid)
		return
	}
	storage := s.server.Storage

	result := SsiUpdateSuccess
	var pendingPushes []presencePush
	privacyChanged := false

	pos := 0
loop:
	for pos+10 <= len(data) {
		nameLen := int(getBE16(data, pos))
		pos += 2
		if pos+nameLen+8 > len(data) {
			break
		}
		name := string(data[pos : pos+nameLen])
		pos += nameLen
		groupID := getBE16(data, pos)
		pos += 2
		itemID := getBE16(data, pos)
		pos += 2
		itemType := getBE16(data, pos)
		pos += 2
		tlvLen := int(getBE16(data, pos))
		pos += 2
		if pos+tlvLen > len(data) {
			break
		}
		tlvData := data[pos : pos+tlvLen]
		pos += tlvLen
		tlvs := parseTLVs(tlvData)

		switch itemType {
		case 0x0001:
			if groupID == SsiMasterGroupID {

				if isDelete {
					continue
				}
				storage.UpsertGroup(s.uin, SsiMasterGroupID, "")
				if c8, ok := tlvs[0x00C8]; ok {
					var ids []uint16
					ip := 0
					for ip+2 <= len(c8) {
						ids = append(ids, getBE16(c8, ip))
						ip += 2
					}
					storage.SetGroupItems(s.uin, SsiMasterGroupID, ids)
				}
				continue
			}
			if isAdd {
				actualGroupID := storage.GetOrCreateGroupByName(s.uin, groupID, name)
				if actualGroupID != groupID {
					s.ssiGroupRemap[groupID] = actualGroupID
				}
			} else if isDelete {

				if groupID == SsiGeneralGroupID {
					named := 0
					for _, g := range user.Groups {
						if g.GroupID != SsiMasterGroupID && g.Name != "" {
							named++
						}
					}
					if named <= 1 {
						continue
					}
				}
				storage.DeleteGroup(s.uin, groupID)
			} else if isUpdate {
				if existingGroup, ok := user.Groups[groupID]; ok {
					if name != "" && name != existingGroup.Name {
						storage.UpsertGroup(s.uin, groupID, name)
					}
					c8, ok2 := tlvs[0x00C8]
					if ok2 {
						var ids []uint16
						ip := 0
						for ip+2 <= len(c8) {
							ids = append(ids, getBE16(c8, ip))
							ip += 2
						}
						storage.SetGroupItems(s.uin, groupID, ids)
					}
				}
			}
		case 0x0000:
			if groupID == SsiMasterGroupID {
				var named []*GroupEntry
				for _, g := range user.Groups {
					if g.GroupID != SsiMasterGroupID && g.Name != "" {
						named = append(named, g)
					}
				}
				sort.Slice(named, func(i, j int) bool { return named[i].GroupID < named[j].GroupID })
				if len(named) > 0 {
					groupID = named[0].GroupID
				} else {
					newGid := storage.GetOrCreateGroupByName(s.uin, SsiGeneralGroupID, SsiGeneralGroupName)
					groupID = newGid
					user.Groups[newGid] = &GroupEntry{GroupID: newGid, Name: SsiGeneralGroupName}
				}
			}
			if remapped, ok := s.ssiGroupRemap[groupID]; ok {
				groupID = remapped
			}
			nick := ""
			if rawNick, ok := tlvs[0x0131]; ok {
				nick = trimNul(string(rawNick))
			}
			_, pending := tlvs[0x0066]

			if isAdd {
				if !storage.UserExists(name) {
					result = SsiUpdateNotFound
					break loop
				}
				if !pending && storage.GetAuthRequired(name) {
					storage.UpsertContact(s.uin, name, groupID, itemID, nick, true)
					if _, ok := user.Groups[groupID]; ok {
						storage.AddGroupItem(s.uin, groupID, itemID)
					}
					result = SsiUpdateAuthRequired
					break loop
				}
				storage.UpsertContact(s.uin, name, groupID, itemID, nick, pending)
				if _, ok := user.Groups[groupID]; ok {
					storage.AddGroupItem(s.uin, groupID, itemID)
				}
				if !pending {
					addedSession := s.server.getSession(name)
					if addedSession != nil {
						uinB := []byte(s.uin)
						payload := append([]byte{byte(len(uinB))}, uinB...)
						target := addedSession
						s.spawn(func() { target.sendSnac(0x0013, SsiYouWereAdded, payload, noReqID, 0) })

						addedUser, err := s.server.Storage.GetUser(name)
						_, selfInAddedContacts := func() (*ContactEntry, bool) {
							if addedUser == nil {
								return nil, false
							}
							c, ok := addedUser.Contacts[s.uin]
							return c, ok
						}()
						if err == nil && addedUser != nil && privacyVisible(addedUser, s.uin, selfInAddedContacts) {
							pendingPushes = append(pendingPushes, presencePush{
								uin: name, online: true, status: addedSession.status, caps: addedSession.caps, xstat: addedSession.xstatusRaw,
							})
						}
					} else {

						pendingPushes = append(pendingPushes, presencePush{uin: name, online: false})
					}
				}
			} else if isDelete {
				storage.DeleteContact(s.uin, name)
				if _, ok := user.Groups[groupID]; ok {
					storage.RemoveGroupItem(s.uin, groupID, itemID)
				}
			} else if isUpdate {
				if existing, ok := user.Contacts[name]; ok {
					oldGroupID := existing.GroupID
					storage.UpsertContact(s.uin, name, groupID, itemID, nick, pending)
					if oldGroupID != groupID {
						if _, ok := user.Groups[oldGroupID]; ok {
							storage.RemoveGroupItem(s.uin, oldGroupID, itemID)
						}
						if _, ok := user.Groups[groupID]; ok {
							storage.AddGroupItem(s.uin, groupID, itemID)
						}
					}
				}
			}
		case SsiItemPermit, SsiItemDeny:
			if isAdd || isUpdate {
				storage.UpsertPrivacyItem(s.uin, int(itemType), name, itemID)
			} else if isDelete {
				storage.DeletePrivacyItem(s.uin, int(itemType), name)
			}
			privacyChanged = true
		case SsiItemPDInfo:
			if isDelete {
				storage.SetPDMode(s.uin, PDModePermitAll)
			} else {
				mode := PDModePermitAll
				if modeB, ok := tlvs[TlvPDMode]; ok && len(modeB) >= 1 {
					mode = int(modeB[0])
				}
				storage.SetPDMode(s.uin, mode)
			}
			privacyChanged = true
		default:

			if isDelete {
				storage.DeleteMiscItem(s.uin, groupID, itemID, itemType)
			} else {
				storage.UpsertMiscItem(s.uin, groupID, itemID, itemType, name, tlvData)
			}
		}
	}

	s.sendSSIAck(result, reqid)

	if result == SsiUpdateSuccess {
		storage.TouchSsiMod(s.uin)
		for _, push := range pendingPushes {
			if push.online {
				s.sendBuddyOnline(push.uin, push.status, push.caps, push.xstat)
			} else {
				s.sendBuddyOffline(push.uin)
			}
		}
		if privacyChanged {
			s.applyPrivacyChange()
		}
	}
}

func (s *Session) applyPrivacyChange() {
	user, err := s.server.Storage.GetUser(s.uin)
	if err != nil || user == nil {
		return
	}
	s.server.forEachSession(func(otherUin string, sess *Session) {
		var otherUser *UserAccount
		if otherUin == s.uin {
			otherUser = user
		} else {
			otherUser, _ = s.server.Storage.GetUser(otherUin)
		}
		if otherUser == nil {
			return
		}
		if _, ok := otherUser.Contacts[s.uin]; !ok {
			return
		}
		if privacyVisible(user, otherUin, true) && !pendingAuthHidesPresence(otherUser, s.uin) {
			s.spawn(func() { sess.sendBuddyOnline(s.uin, s.status, s.caps, s.xstatusRaw) })
		} else {
			s.spawn(func() { sess.sendBuddyOffline(s.uin) })
		}
	})
}

func (s *Session) deliverPendingAuthRequests() {
	reqs := s.server.Storage.GetPendingAuthRequests(s.uin)
	if len(reqs) == 0 {
		return
	}
	for _, r := range reqs {
		uinB := []byte(r.FromUIN)
		reasonB := []byte(r.Reason)
		fwd := append([]byte{byte(len(uinB))}, uinB...)
		fwd = append(fwd, beU16(uint16(len(reasonB)))...)
		fwd = append(fwd, reasonB...)
		fwd = append(fwd, beU16(0)...)
		s.sendSnac(0x0013, SsiAuthReq, fwd, noReqID, 0)
	}
	s.server.Storage.ClearPendingAuthRequests(s.uin)
}

func (s *Session) handleAuthSendReq(data []byte) {
	defer func() { recover() }()
	pos := 0
	if pos >= len(data) {
		return
	}
	uinLen := int(data[pos])
	pos++
	toUin := string(data[pos : pos+uinLen])
	pos += uinLen
	reasonLen := int(getBE16(data, pos))
	pos += 2
	reason := string(data[pos : pos+reasonLen])
	target := s.server.getSession(toUin)
	if target == nil {
		s.server.Storage.AddPendingAuthRequest(toUin, s.uin, reason)
		return
	}
	uinB := []byte(s.uin)
	reasonB := []byte(reason)
	fwd := append([]byte{byte(len(uinB))}, uinB...)
	fwd = append(fwd, beU16(uint16(len(reasonB)))...)
	fwd = append(fwd, reasonB...)
	fwd = append(fwd, beU16(0)...)
	s.spawn(func() { target.sendSnac(0x0013, SsiAuthReq, fwd, noReqID, 0) })
}

func (s *Session) handleAuthSendReply(data []byte) {
	defer func() { recover() }()
	pos := 0
	if pos >= len(data) {
		return
	}
	uinLen := int(data[pos])
	pos++
	toUin := string(data[pos : pos+uinLen])
	pos += uinLen
	if pos >= len(data) {
		return
	}
	granted := data[pos] == 0x01
	pos++
	msgLen := int(getBE16(data, pos))
	pos += 2
	msg := string(data[pos : pos+msgLen])

	if granted {
		s.server.Storage.ClearPendingAuth(toUin, s.uin)
	}

	target := s.server.getSession(toUin)
	if target != nil {
		uinB := []byte(s.uin)
		msgB := []byte(msg)
		fwd := append([]byte{byte(len(uinB))}, uinB...)
		var g byte
		if granted {
			g = 0x01
		}
		fwd = append(fwd, g)
		fwd = append(fwd, beU16(uint16(len(msgB)))...)
		fwd = append(fwd, msgB...)
		s.spawn(func() { target.sendSnac(0x0013, SsiAuthReply, fwd, noReqID, 0) })
	}
	if granted && target != nil {
		uinB := []byte(s.uin)
		payload := append([]byte{byte(len(uinB))}, uinB...)
		s.spawn(func() { target.sendSnac(0x0013, SsiYouWereAdded, payload, noReqID, 0) })

		selfUser, err := s.server.Storage.GetUser(s.uin)
		if err == nil && selfUser != nil && privacyVisible(selfUser, toUin, true) {
			status, caps, xstat := s.status, s.caps, s.xstatusRaw
			s.spawn(func() { target.sendBuddyOnline(s.uin, status, caps, xstat) })
		}
	}
}

func (s *Session) handleDeleteYourself(data []byte) {
	if len(data) < 1 {
		return
	}
	uinLen := int(data[0])
	if len(data) < 1+uinLen {
		return
	}
	targetUin := string(data[1 : 1+uinLen])

	targetUser, err := s.server.Storage.GetUser(targetUin)
	if err != nil || targetUser == nil {
		return
	}
	contact, hadContact := targetUser.Contacts[s.uin]
	s.server.Storage.DeleteContact(targetUin, s.uin)
	if hadContact {
		if _, ok := targetUser.Groups[contact.GroupID]; ok {
			s.server.Storage.RemoveGroupItem(targetUin, contact.GroupID, contact.ItemID)
		}
	}
	if targetSession := s.server.getSession(targetUin); targetSession != nil && hadContact {
		s.spawn(func() { targetSession.sendBuddyOffline(s.uin) })
	}
}
