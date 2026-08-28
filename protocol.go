package main

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"math/rand"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/text/encoding/charmap"
)

func beU16(v uint16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, v); return b }
func beU32(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }
func leU16(v uint16) []byte { b := make([]byte, 2); binary.LittleEndian.PutUint16(b, v); return b }
func leU32(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }

func getBE16(b []byte, off int) uint16 { return binary.BigEndian.Uint16(b[off:]) }
func getBE32(b []byte, off int) uint32 { return binary.BigEndian.Uint32(b[off:]) }
func getLE16(b []byte, off int) uint16 { return binary.LittleEndian.Uint16(b[off:]) }
func getLE32(b []byte, off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }

func makeTLV(t uint16, v []byte) []byte {
	out := make([]byte, 0, 4+len(v))
	out = append(out, beU16(t)...)
	out = append(out, beU16(uint16(len(v)))...)
	out = append(out, v...)
	return out
}

func parseTLVs(data []byte) map[uint16][]byte {
	out := map[uint16][]byte{}
	p := 0
	for p+4 <= len(data) {
		t := getBE16(data, p)
		l := int(getBE16(data, p+2))
		if p+4+l > len(data) {
			break
		}
		out[t] = data[p+4 : p+4+l]
		p += 4 + l
	}
	return out
}

func packFlap(channel byte, seq uint16, payload []byte) []byte {
	out := make([]byte, 0, 6+len(payload))
	out = append(out, 0x2A, channel)
	out = append(out, beU16(seq)...)
	out = append(out, beU16(uint16(len(payload)))...)
	out = append(out, payload...)
	return out
}

func makeSnac(fam, sub, flags uint16, reqid uint32, payload []byte) []byte {
	out := make([]byte, 0, 10+len(payload))
	out = append(out, beU16(fam)...)
	out = append(out, beU16(sub)...)
	out = append(out, beU16(flags)...)
	out = append(out, beU32(reqid)...)
	out = append(out, payload...)
	return out
}

var cp1251 = charmap.Windows1251

func encodeCP1251(s string) []byte {
	b, err := cp1251.NewEncoder().Bytes([]byte(s))
	if err != nil {
		out := make([]byte, 0, len(s))
		for _, r := range s {
			if eb, err2 := cp1251.NewEncoder().Bytes([]byte(string(r))); err2 == nil {
				out = append(out, eb...)
			} else {
				out = append(out, '?')
			}
		}
		return out
	}
	return b
}

func decodeCP1251(b []byte) string {
	out, err := cp1251.NewDecoder().Bytes(b)
	if err != nil {
		return string(b)
	}
	return string(out)
}

func makeAsciizLE(text string) []byte {
	raw := []byte(text)
	out := make([]byte, 0, 2+len(raw)+1)
	out = append(out, leU16(uint16(len(raw)+1))...)
	out = append(out, raw...)
	out = append(out, 0)
	return out
}

func makeAsciizLEIcq(text string) []byte {
	if text == "" {
		return append(leU16(1), 0)
	}
	raw := encodeCP1251(text)
	out := make([]byte, 0, 2+len(raw)+1)
	out = append(out, leU16(uint16(len(raw)+1))...)
	out = append(out, raw...)
	out = append(out, 0)
	return out
}

func encodeSSIName(name string) []byte { return []byte(name) }

func packSSIEntry(name []byte, groupID, itemID, itemType uint16, tlvs []byte) []byte {
	out := make([]byte, 0)
	out = append(out, beU16(uint16(len(name)))...)
	out = append(out, name...)
	out = append(out, beU16(groupID)...)
	out = append(out, beU16(itemID)...)
	out = append(out, beU16(itemType)...)
	out = append(out, beU16(uint16(len(tlvs)))...)
	out = append(out, tlvs...)
	return out
}

func buildSSIData(groupOrder []uint16, groups map[uint16]*GroupEntry, contacts map[string]*ContactEntry,
	permit, deny map[string]uint16, pdMode int, udate uint32, miscItems map[MiscSSIKey]*MiscSsiItem) []byte {

	contactsByGroup := map[uint16][]*ContactEntry{}
	for _, c := range contacts {
		contactsByGroup[c.GroupID] = append(contactsByGroup[c.GroupID], c)
	}
	for gid := range contactsByGroup {
		lst := contactsByGroup[gid]
		for i := 1; i < len(lst); i++ {
			j := i
			for j > 0 && lst[j-1].ItemID > lst[j].ItemID {
				lst[j-1], lst[j] = lst[j], lst[j-1]
				j--
			}
		}
	}

	packContact := func(c *ContactEntry) []byte {
		nameB := []byte(c.UIN)
		var tlvs []byte
		if c.Nick != "" {
			nickB := []byte(c.Nick)
			tlvs = append(tlvs, beU16(0x0131)...)
			tlvs = append(tlvs, beU16(uint16(len(nickB)))...)
			tlvs = append(tlvs, nickB...)
		}
		if c.PendingAuth {
			tlvs = append(tlvs, beU16(0x0066)...)
			tlvs = append(tlvs, beU16(0)...)
		}
		return packSSIEntry(nameB, c.GroupID, c.ItemID, 0x0000, tlvs)
	}

	var entries []byte
	groupCountEmitted := 0
	for _, gid := range groupOrder {
		g := groups[gid]
		if g == nil {
			continue
		}
		nameB := encodeSSIName(g.Name)
		var childIDs []uint16
		if gid == SsiMasterGroupID {
			childIDs = g.ItemIDs
		} else {
			for _, c := range contactsByGroup[gid] {
				childIDs = append(childIDs, c.ItemID)
			}
		}
		var tlvs []byte
		if len(childIDs) > 0 {
			var idsData []byte
			for _, iid := range childIDs {
				idsData = append(idsData, beU16(iid)...)
			}
			tlvs = append(tlvs, beU16(0x00C8)...)
			tlvs = append(tlvs, beU16(uint16(len(idsData)))...)
			tlvs = append(tlvs, idsData...)
		}
		entries = append(entries, packSSIEntry(nameB, g.GroupID, 0, 0x0001, tlvs)...)
		groupCountEmitted++
		for _, c := range contactsByGroup[gid] {
			entries = append(entries, packContact(c)...)
		}
		delete(contactsByGroup, gid)
	}
	var remainingGids []uint16
	for gid := range contactsByGroup {
		remainingGids = append(remainingGids, gid)
	}
	for i := 1; i < len(remainingGids); i++ {
		j := i
		for j > 0 && remainingGids[j-1] > remainingGids[j] {
			remainingGids[j-1], remainingGids[j] = remainingGids[j], remainingGids[j-1]
			j--
		}
	}
	for _, gid := range remainingGids {
		for _, c := range contactsByGroup[gid] {
			entries = append(entries, packContact(c)...)
		}
	}

	extraCount := len(permit) + len(deny)
	for target, itemID := range permit {
		entries = append(entries, packSSIEntry([]byte(target), 0, itemID, SsiItemPermit, nil)...)
	}
	for target, itemID := range deny {
		entries = append(entries, packSSIEntry([]byte(target), 0, itemID, SsiItemDeny, nil)...)
	}
	if pdMode != 0 && pdMode != PDModePermitAll {
		pdinfoTlv := makeTLV(TlvPDMode, []byte{byte(pdMode)})
		entries = append(entries, packSSIEntry(nil, 0, 0, SsiItemPDInfo, pdinfoTlv)...)
		extraCount++
	}

	if len(miscItems) > 0 {
		keys := make([]MiscSSIKey, 0, len(miscItems))
		for k := range miscItems {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if keys[i].GroupID != keys[j].GroupID {
				return keys[i].GroupID < keys[j].GroupID
			}
			if keys[i].ItemID != keys[j].ItemID {
				return keys[i].ItemID < keys[j].ItemID
			}
			return keys[i].ItemType < keys[j].ItemType
		})
		for _, k := range keys {
			item := miscItems[k]
			var nameB []byte
			if item.Name != "" {
				nameB = []byte(item.Name)
			}
			entries = append(entries, packSSIEntry(nameB, item.GroupID, item.ItemID, item.ItemType, item.TlvData)...)
		}
		extraCount += len(miscItems)
	}

	if udate == 0 {
		udate = uint32(time.Now().Unix())
	}
	total := groupCountEmitted + len(contacts) + extraCount

	out := make([]byte, 0)
	out = append(out, 0)
	out = append(out, beU16(uint16(total))...)
	out = append(out, entries...)
	out = append(out, beU32(udate)...)
	return out
}

func pendingAuthHidesPresence(viewer *UserAccount, targetUin string) bool {
	entry, ok := viewer.Contacts[targetUin]
	return ok && entry.PendingAuth
}

func privacyVisible(owner *UserAccount, viewerUin string, viewerHasOwnerInContacts bool) bool {
	if _, ok := owner.Deny[viewerUin]; ok {
		return false
	}
	if _, ok := owner.Permit[viewerUin]; ok {
		return true
	}
	mode := owner.PDMode
	if mode == 0 {
		mode = PDModePermitAll
	}
	switch mode {
	case PDModeDenyAll:
		return false
	case PDModePermitSome:
		return false
	case PDModePermitBuddies:
		return viewerHasOwnerInContacts
	}
	return true
}

const cookieLen = 256

func makeCookie(uin string) []byte {
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ?@{}"
	prefix := []byte(uin)
	if len(prefix) >= cookieLen {
		return prefix[:cookieLen]
	}
	fill := cookieLen - len(prefix)
	rndLen := fill
	if rndLen > 48 {
		rndLen = 48
	}
	out := make([]byte, 0, cookieLen)
	out = append(out, prefix...)
	for i := 0; i < rndLen; i++ {
		out = append(out, alphabet[rand.Intn(len(alphabet))])
	}
	for i := 0; i < fill-rndLen; i++ {
		out = append(out, 'A')
	}
	return out
}

func isUnusableBosIP(ip string) bool {
	if ip == "" {
		return true
	}
	ip = strings.ToLower(strings.TrimSpace(strings.SplitN(ip, "%", 2)[0]))
	switch ip {
	case "0.0.0.0", "::", "::1", "localhost":
		return true
	}
	return strings.HasPrefix(ip, "127.")
}

func guessLanIPv4() string {
	conn, err := net.DialTimeout("udp", "8.8.8.8:80", 500*time.Millisecond)
	if err != nil {
		return ""
	}
	defer conn.Close()
	host, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil || isUnusableBosIP(host) {
		return ""
	}
	return host
}

func pickBosHost(configured, sockIP, peerIP string) string {
	configured = strings.TrimSpace(configured)
	if configured != "" {
		return configured
	}
	if sockIP != "" && !isUnusableBosIP(sockIP) {
		return sockIP
	}
	if peerIP != "" && !isUnusableBosIP(peerIP) {
		if lan := guessLanIPv4(); lan != "" {
			return lan
		}
	}
	if sockIP != "" {
		return sockIP
	}
	return "127.0.0.1"
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

var basicRateInfo = mustHex(
	"0005000100000050000009c4000003e8000001f40000012c00001edc00001f40" +
		"000000000000020000005000000bb8000003e8000001f40000012c00001af4" +
		"00001b5800000000000003000000140000100400000fa000000bb8000007d0" +
		"00001af400001b58000000000000040000001400001194000010cc00000c80" +
		"000007d000001edc00001f40000000000000050000000a00001194000010cc" +
		"00000c80000007d0000022c40000232800000000000001009a000100010001" +
		"00020001000300010004000100050001000600010007000100080001000900" +
		"01000a0001000b0001000c0001000d0001000e0001000f0001001000010011" +
		"00010012000100130001001400010015000100160001001700010018000100" +
		"190001001a0001001b0001001c0001001c0001001e0001001f000100200001" +
		"00210002000100020002000200030002000400020006000200070002000800" +
		"02000a0002000c0002000d0002000e0002000f000200100002001100020012" +
		"00020013000200140002001500030001000300020003000300030006000300" +
		"0700030008000300090003000a0003000b0003000c00040001000400020004" +
		"000300040004000400050004000700040008000400090004000a0004000b00" +
		"04000c0004000d0004000e0004000f00040010000400110004001200040013" +
		"00040014000600010006000200060003000700010007000200070003000700" +
		"04000700050007000600070007000700080007000900080001000800020009" +
		"0001000900020009000300090004000900090009000a0009000b000a000100" +
		"0a0002000a0003000b0001000b0002000b0003000b0004000c0001000c0002" +
		"000c0003001300010013000200130003001300040013000500130006001300" +
		"0700130008001300090013000a0013000b0013000c0013000d0013000e0013" +
		"000f0013001000130011001300120013001300130014001300150013001600" +
		"13001700130018001300190013001a0013001b0013001d0013001d0013001e" +
		"0013001f001300200013002100130022001300230013002400130025001300" +
		"26001300270013002800150001001500020015000300020006000300040003" +
		"00050009000500090006000900070009000800030002000200050004000600" +
		"040002000200090002000b00050000",
)

func makeMD5AuthKey() string {
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	body := make([]byte, 16)
	for i := range body {
		body[i] = alphabet[rand.Intn(len(alphabet))]
	}
	return string(body)
}

func aimMD5Digest(authkey, password string, newMethod bool) []byte {
	authkeyB := []byte(authkey)
	passwordB := []byte(password)
	if newMethod {
		sum := md5.Sum(passwordB)
		passwordB = sum[:]
	}
	h := md5.New()
	h.Write(authkeyB)
	h.Write(passwordB)
	h.Write(AimMD5String)
	return h.Sum(nil)
}

var emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
var homepageRe = regexp.MustCompile(`(?i)^(https?|ftp)://\S+$`)

func validateProfileText(text string, maxLen int) string {
	if strings.ContainsRune(text, '\ufffd') {
		return ""
	}
	for _, ch := range text {
		if (ch < 0x20 && ch != '\t') || ch == 0x7F {
			return ""
		}
	}
	text = strings.TrimSpace(text)
	if len([]byte(text)) > maxLen {
		return ""
	}
	return text
}

func validateEmail(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	if len(text) > 255 || !emailRe.MatchString(text) {
		return ""
	}
	return text
}

func validateHomepage(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	if len(text) > 255 || !homepageRe.MatchString(text) {
		return ""
	}
	return text
}

func validateBirthday(day, mon, year int) string {
	currentYear := time.Now().Year()
	if year < 1900 || year > currentYear {
		return ""
	}
	if mon < 1 || mon > 12 || day < 1 {
		return ""
	}
	t := time.Date(year, time.Month(mon), 1, 0, 0, 0, 0, time.UTC)
	daysInMonth := t.AddDate(0, 1, -1).Day()
	if day > daysInMonth {
		return ""
	}
	return pad2(day) + "." + pad2(mon) + "." + strconv.Itoa(year)
}

func pad2(v int) string {
	s := strconv.Itoa(v)
	if len(s) < 2 {
		return "0" + s
	}
	return s
}

func ensureMsgFeaturesTLV(channel uint16, rawTLVsData []byte) []byte {
	if channel != 1 {
		return rawTLVsData
	}
	var out []byte
	p := 0
	n := len(rawTLVsData)
	for p+4 <= n {
		t := getBE16(rawTLVsData, p)
		l := int(getBE16(rawTLVsData, p+2))
		if p+4+l > n {
			out = append(out, rawTLVsData[p:]...)
			p = n
			break
		}
		val := rawTLVsData[p+4 : p+4+l]
		p += 4 + l

		if t == 0x0002 {
			hasFeatures := false
			ip := 0
			first0101Pos := -1
			vn := len(val)
			for ip+4 <= vn {
				it := getBE16(val, ip)
				il := int(getBE16(val, ip+2))
				if ip+4+il > vn {
					break
				}
				if it == 0x0501 {
					hasFeatures = true
					break
				}
				if it == 0x0101 && first0101Pos == -1 {
					first0101Pos = ip
				}
				ip += 4 + il
			}
			if !hasFeatures {
				featuresTlv := makeTLV(0x0501, []byte{0x01})
				insertAt := first0101Pos
				if insertAt == -1 {
					insertAt = 0
				}
				newVal := make([]byte, 0, len(val)+len(featuresTlv))
				newVal = append(newVal, val[:insertAt]...)
				newVal = append(newVal, featuresTlv...)
				newVal = append(newVal, val[insertAt:]...)
				val = newVal
			}
		}
		out = append(out, beU16(t)...)
		out = append(out, beU16(uint16(len(val)))...)
		out = append(out, val...)
	}
	if p < n {
		out = append(out, rawTLVsData[p:]...)
	}
	return out
}
