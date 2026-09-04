package main

import (
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS users (
    uin TEXT PRIMARY KEY,
    password TEXT NOT NULL DEFAULT '',
    ssi_mod_date INTEGER NOT NULL DEFAULT 0,
    ssi_item_count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS profiles (
    uin TEXT PRIMARY KEY REFERENCES users(uin) ON DELETE CASCADE,
    nick TEXT NOT NULL DEFAULT '',
    first_name TEXT NOT NULL DEFAULT '',
    last_name TEXT NOT NULL DEFAULT '',
    email TEXT NOT NULL DEFAULT '',
    city TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT '',
    phone TEXT NOT NULL DEFAULT '',
    fax TEXT NOT NULL DEFAULT '',
    address TEXT NOT NULL DEFAULT '',
    cell_phone TEXT NOT NULL DEFAULT '',
    age INTEGER NOT NULL DEFAULT 0,
    gender TEXT NOT NULL DEFAULT '',
    home_page TEXT NOT NULL DEFAULT '',
    birthday TEXT NOT NULL DEFAULT '',
    about TEXT NOT NULL DEFAULT '',
    work_city TEXT NOT NULL DEFAULT '',
    work_state TEXT NOT NULL DEFAULT '',
    work_phone TEXT NOT NULL DEFAULT '',
    work_fax TEXT NOT NULL DEFAULT '',
    work_addr TEXT NOT NULL DEFAULT '',
    work_name TEXT NOT NULL DEFAULT '',
    work_dep TEXT NOT NULL DEFAULT '',
    work_pos TEXT NOT NULL DEFAULT '',
    auth_required INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS groups_tbl (
    uin TEXT NOT NULL REFERENCES users(uin) ON DELETE CASCADE,
    group_id INTEGER NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (uin, group_id)
);
CREATE TABLE IF NOT EXISTS group_items (
    uin TEXT NOT NULL,
    group_id INTEGER NOT NULL,
    item_id INTEGER NOT NULL,
    position INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (uin, group_id, item_id)
);
CREATE TABLE IF NOT EXISTS contacts (
    uin TEXT NOT NULL REFERENCES users(uin) ON DELETE CASCADE,
    contact_uin TEXT NOT NULL,
    group_id INTEGER NOT NULL,
    item_id INTEGER NOT NULL,
    nick TEXT NOT NULL DEFAULT '',
    pending_auth INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (uin, contact_uin)
);
CREATE TABLE IF NOT EXISTS privacy_items (
    uin TEXT NOT NULL REFERENCES users(uin) ON DELETE CASCADE,
    item_type INTEGER NOT NULL,
    target_uin TEXT NOT NULL,
    item_id INTEGER NOT NULL,
    PRIMARY KEY (uin, item_type, target_uin)
);
CREATE TABLE IF NOT EXISTS privacy_mode (
    uin TEXT PRIMARY KEY REFERENCES users(uin) ON DELETE CASCADE,
    pd_mode INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS misc_ssi_items (
    uin TEXT NOT NULL REFERENCES users(uin) ON DELETE CASCADE,
    group_id INTEGER NOT NULL,
    item_id INTEGER NOT NULL,
    item_type INTEGER NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    tlv_data BLOB NOT NULL DEFAULT '',
    PRIMARY KEY (uin, group_id, item_id, item_type)
);
CREATE TABLE IF NOT EXISTS offline_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    to_uin TEXT NOT NULL REFERENCES users(uin) ON DELETE CASCADE,
    from_uin TEXT NOT NULL,
    text TEXT NOT NULL DEFAULT '',
    timestamp REAL NOT NULL,
    msg_type INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_offline_to_uin ON offline_messages(to_uin);
CREATE TABLE IF NOT EXISTS pending_auth_requests (
    to_uin TEXT NOT NULL REFERENCES users(uin) ON DELETE CASCADE,
    from_uin TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    timestamp REAL NOT NULL,
    PRIMARY KEY (to_uin, from_uin)
);
CREATE INDEX IF NOT EXISTS idx_pending_auth_to_uin ON pending_auth_requests(to_uin);
`

type Storage struct {
	mu     sync.Mutex
	db     *sql.DB
	dbPath string
}

func NewStorage(dbPath string) (*Storage, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	migrateColumn(db, "users", "ssi_mod_date", "INTEGER NOT NULL DEFAULT 0")
	migrateColumn(db, "users", "ssi_item_count", "INTEGER NOT NULL DEFAULT 0")
	s := &Storage{db: db, dbPath: dbPath}
	s.createDefaultUsers()
	return s, nil
}

func migrateColumn(db *sql.DB, table, column, ddl string) {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return
	}
	found := false
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk) == nil && name == column {
			found = true
		}
	}
	rows.Close()
	if !found {
		db.Exec("ALTER TABLE " + table + " ADD COLUMN " + column + " " + ddl)
	}
}

func (s *Storage) createDefaultUsers() {
	defaults := [][2]string{{"123456", "test"}, {"111111", "pass"}, {"222222", "pass"}}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range defaults {
		s.db.Exec("INSERT OR IGNORE INTO users (uin, password) VALUES (?, ?)", d[0], d[1])
		s.db.Exec("INSERT OR IGNORE INTO profiles (uin) VALUES (?)", d[0])
	}
}

func (s *Storage) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Close()
}

func (s *Storage) rowToAccount(uin, password string, ssiModDate uint32, ssiItemCount uint16) (*UserAccount, error) {
	acc := newUserAccount(uin)
	acc.Password = password
	acc.SsiModDate = ssiModDate
	acc.SsiItemCount = ssiItemCount

	prow := s.db.QueryRow(`SELECT nick,first_name,last_name,email,city,state,phone,fax,address,
		cell_phone,age,gender,home_page,birthday,about,work_city,work_state,work_phone,work_fax,
		work_addr,work_name,work_dep,work_pos,auth_required FROM profiles WHERE uin = ?`, uin)
	var authReq int
	err := prow.Scan(&acc.Profile.Nick, &acc.Profile.FirstName, &acc.Profile.LastName, &acc.Profile.Email,
		&acc.Profile.City, &acc.Profile.State, &acc.Profile.Phone, &acc.Profile.Fax, &acc.Profile.Address,
		&acc.Profile.CellPhone, &acc.Profile.Age, &acc.Profile.Gender, &acc.Profile.HomePage,
		&acc.Profile.Birthday, &acc.Profile.About, &acc.Profile.WorkCity, &acc.Profile.WorkState,
		&acc.Profile.WorkPhone, &acc.Profile.WorkFax, &acc.Profile.WorkAddr, &acc.Profile.WorkName,
		&acc.Profile.WorkDep, &acc.Profile.WorkPos, &authReq)
	if err == nil {
		acc.Profile.AuthRequired = authReq != 0
	}

	grows, err := s.db.Query("SELECT group_id, name FROM groups_tbl WHERE uin = ? ORDER BY group_id", uin)
	if err != nil {
		return nil, err
	}
	var gids []uint16
	for grows.Next() {
		var gid uint16
		var name string
		if err := grows.Scan(&gid, &name); err != nil {
			grows.Close()
			return nil, err
		}
		gids = append(gids, gid)
		acc.Groups[gid] = &GroupEntry{GroupID: gid, Name: name}
		acc.GroupOrder = append(acc.GroupOrder, gid)
	}
	grows.Close()

	for _, gid := range gids {
		irows, err := s.db.Query("SELECT item_id FROM group_items WHERE uin=? AND group_id=? ORDER BY position", uin, gid)
		if err != nil {
			return nil, err
		}
		var ids []uint16
		for irows.Next() {
			var iid uint16
			irows.Scan(&iid)
			ids = append(ids, iid)
		}
		irows.Close()
		acc.Groups[gid].ItemIDs = ids
	}

	crows, err := s.db.Query("SELECT contact_uin, group_id, item_id, nick, pending_auth FROM contacts WHERE uin=?", uin)
	if err != nil {
		return nil, err
	}
	for crows.Next() {
		var cuin, nick string
		var gid, iid uint16
		var pending int
		crows.Scan(&cuin, &gid, &iid, &nick, &pending)
		acc.Contacts[cuin] = &ContactEntry{UIN: cuin, GroupID: gid, ItemID: iid, Nick: nick, PendingAuth: pending != 0}
	}
	crows.Close()

	maxItem := 0
	for _, c := range acc.Contacts {
		if int(c.ItemID) > maxItem {
			maxItem = int(c.ItemID)
		}
	}
	for _, g := range acc.Groups {
		if int(g.GroupID) > maxItem {
			maxItem = int(g.GroupID)
		}
	}

	prows, err := s.db.Query("SELECT item_type, target_uin, item_id FROM privacy_items WHERE uin=?", uin)
	if err != nil {
		return nil, err
	}
	for prows.Next() {
		var itemType int
		var target string
		var iid uint16
		prows.Scan(&itemType, &target, &iid)
		if int(iid) > maxItem {
			maxItem = int(iid)
		}
		if itemType == SsiItemPermit {
			acc.Permit[target] = iid
		} else if itemType == SsiItemDeny {
			acc.Deny[target] = iid
		}
	}
	prows.Close()

	var pdMode sql.NullInt64
	s.db.QueryRow("SELECT pd_mode FROM privacy_mode WHERE uin=?", uin).Scan(&pdMode)
	if pdMode.Valid {
		acc.PDMode = int(pdMode.Int64)
	}

	mrows, err := s.db.Query("SELECT group_id, item_id, item_type, name, tlv_data FROM misc_ssi_items WHERE uin=?", uin)
	if err != nil {
		return nil, err
	}
	for mrows.Next() {
		var gid, iid, itype uint16
		var name string
		var tlvData []byte
		mrows.Scan(&gid, &iid, &itype, &name, &tlvData)
		if int(iid) > maxItem {
			maxItem = int(iid)
		}
		key := MiscSSIKey{GroupID: gid, ItemID: iid, ItemType: itype}
		acc.MiscItems[key] = &MiscSsiItem{Name: name, GroupID: gid, ItemID: iid, ItemType: itype, TlvData: tlvData}
	}
	mrows.Close()

	acc.NextItemID = maxItem + 1
	return acc, nil
}

func (s *Storage) GetUser(uin string) (*UserAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var password string
	var ssiModDate uint32
	var ssiItemCount uint16
	err := s.db.QueryRow("SELECT password, ssi_mod_date, ssi_item_count FROM users WHERE uin=?", uin).
		Scan(&password, &ssiModDate, &ssiItemCount)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.rowToAccount(uin, password, ssiModDate, ssiItemCount)
}

func (s *Storage) RegisterNewUser(password string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var m sql.NullInt64
	s.db.QueryRow("SELECT MAX(CAST(uin AS INTEGER)) AS m FROM users").Scan(&m)
	newUin := int64(0)
	if m.Valid {
		newUin = m.Int64
	}
	newUin++
	if newUin < NewUinFloor {
		newUin += NewUinFloor
	}
	uinStr := strconv.FormatInt(newUin, 10)
	if _, err := s.db.Exec("INSERT INTO users (uin, password) VALUES (?, ?)", uinStr, password); err != nil {
		return "", err
	}
	s.db.Exec("INSERT INTO profiles (uin) VALUES (?)", uinStr)
	return uinStr, nil
}

func xorPassword(password string) []byte {
	key := []byte{0xF3, 0x26, 0x81, 0xC4, 0x39, 0x86, 0xDB, 0x92,
		0x71, 0xA3, 0xB9, 0xE6, 0x53, 0x7A, 0x95, 0x7C}
	out := make([]byte, len(password))
	for i := 0; i < len(password); i++ {
		out[i] = key[i%len(key)] ^ password[i]
	}
	return out
}

func (s *Storage) CheckAuth(uin string, passwordXor []byte) bool {
	s.mu.Lock()
	var password string
	err := s.db.QueryRow("SELECT password FROM users WHERE uin=?", uin).Scan(&password)
	s.mu.Unlock()
	if err != nil {
		return false
	}
	expected := xorPassword(password)
	if len(expected) != len(passwordXor) {
		return false
	}
	for i := range expected {
		if expected[i] != passwordXor[i] {
			return false
		}
	}
	return true
}

func (s *Storage) SetPassword(uin, newPassword string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Exec("UPDATE users SET password=? WHERE uin=?", newPassword, uin)
}

func (s *Storage) GetPassword(uin string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var password string
	err := s.db.QueryRow("SELECT password FROM users WHERE uin=?", uin).Scan(&password)
	if err != nil {
		return "", false
	}
	return password, true
}

func (s *Storage) UserExists(uin string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	var one int
	err := s.db.QueryRow("SELECT 1 FROM users WHERE uin=?", uin).Scan(&one)
	return err == nil
}

func (s *Storage) GetAuthRequired(uin string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	var v sql.NullInt64
	err := s.db.QueryRow("SELECT auth_required FROM profiles WHERE uin=?", uin).Scan(&v)
	if err != nil || !v.Valid {
		return true
	}
	return v.Int64 != 0
}

func (s *Storage) SaveProfile(uin string, p UserProfile) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Exec(`UPDATE profiles SET nick=?,first_name=?,last_name=?,email=?,city=?,state=?,phone=?,
		fax=?,address=?,cell_phone=?,age=?,gender=?,home_page=?,birthday=?,about=?,work_city=?,
		work_state=?,work_phone=?,work_fax=?,work_addr=?,work_name=?,work_dep=?,work_pos=?,
		auth_required=? WHERE uin=?`,
		p.Nick, p.FirstName, p.LastName, p.Email, p.City, p.State, p.Phone, p.Fax, p.Address,
		p.CellPhone, p.Age, p.Gender, p.HomePage, p.Birthday, p.About, p.WorkCity, p.WorkState,
		p.WorkPhone, p.WorkFax, p.WorkAddr, p.WorkName, p.WorkDep, p.WorkPos, boolToInt(p.AuthRequired), uin)
}

func (s *Storage) SetAuthRequired(uin string, req bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Exec("UPDATE profiles SET auth_required=? WHERE uin=?", boolToInt(req), uin)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *Storage) UpsertGroup(uin string, groupID uint16, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Exec(`INSERT INTO groups_tbl (uin, group_id, name) VALUES (?, ?, ?)
		ON CONFLICT(uin, group_id) DO UPDATE SET name=excluded.name`, uin, groupID, name)
}

func (s *Storage) GetOrCreateGroupByName(uin string, proposedGroupID uint16, name string) uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var gid uint16
	err := s.db.QueryRow("SELECT group_id FROM groups_tbl WHERE uin=? AND name=? LIMIT 1", uin, name).Scan(&gid)
	if err == nil {
		return gid
	}
	s.db.Exec(`INSERT INTO groups_tbl (uin, group_id, name) VALUES (?, ?, ?)
		ON CONFLICT(uin, group_id) DO UPDATE SET name=excluded.name`, uin, proposedGroupID, name)
	return proposedGroupID
}

func (s *Storage) DeleteGroup(uin string, groupID uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Exec("DELETE FROM groups_tbl WHERE uin=? AND group_id=?", uin, groupID)
}

func (s *Storage) dedupeDuplicateGroupsLocked(uin string) bool {
	rows, err := s.db.Query("SELECT group_id, name FROM groups_tbl WHERE uin=? AND name != ''", uin)
	if err != nil {
		return false
	}
	type row struct {
		gid  uint16
		name string
	}
	var all []row
	for rows.Next() {
		var r row
		rows.Scan(&r.gid, &r.name)
		all = append(all, r)
	}
	rows.Close()

	byName := map[string][]uint16{}
	for _, r := range all {
		key := r.name
		if strings.EqualFold(strings.TrimSpace(key), SsiGeneralGroupName) {
			key = SsiGeneralGroupName
		}
		byName[key] = append(byName[key], r.gid)
	}

	changed := false
	for name, gids := range byName {
		if len(gids) <= 1 {
			continue
		}
		sort.Slice(gids, func(i, j int) bool { return gids[i] < gids[j] })
		var canonical uint16
		var dupes []uint16
		if name == SsiGeneralGroupName {
			canonical = SsiGeneralGroupID
			for _, g := range gids {
				if g != SsiGeneralGroupID {
					dupes = append(dupes, g)
				}
			}
			if len(dupes) == 0 {
				continue
			}
			s.db.Exec("INSERT OR IGNORE INTO groups_tbl (uin, group_id, name) VALUES (?, ?, ?)",
				uin, SsiGeneralGroupID, SsiGeneralGroupName)
		} else {
			canonical = gids[0]
			dupes = gids[1:]
		}
		for _, dup := range dupes {
			s.db.Exec("UPDATE contacts SET group_id=? WHERE uin=? AND group_id=?", canonical, uin, dup)
			s.db.Exec("UPDATE OR IGNORE group_items SET group_id=? WHERE uin=? AND group_id=?", canonical, uin, dup)
			s.db.Exec("DELETE FROM group_items WHERE uin=? AND group_id=?", uin, dup)
			s.db.Exec("DELETE FROM groups_tbl WHERE uin=? AND group_id=?", uin, dup)
		}
		changed = true
	}
	return changed
}

func (s *Storage) DedupeDuplicateGroups(uin string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dedupeDuplicateGroupsLocked(uin)
}

func (s *Storage) EnsureDefaultGroups(uin string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Exec("INSERT OR IGNORE INTO groups_tbl (uin, group_id, name) VALUES (?, ?, ?)", uin, SsiMasterGroupID, "")
	s.db.Exec("INSERT OR IGNORE INTO groups_tbl (uin, group_id, name) VALUES (?, ?, ?)", uin, SsiGeneralGroupID, SsiGeneralGroupName)
	s.dedupeDuplicateGroupsLocked(uin)
}

func (s *Storage) GetSsiModInfo(uin string) (uint32, uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var modDate uint32
	var itemCount uint16
	err := s.db.QueryRow("SELECT ssi_mod_date, ssi_item_count FROM users WHERE uin=?", uin).Scan(&modDate, &itemCount)
	if err != nil {
		return 0, 0
	}
	return modDate, itemCount
}

func (s *Storage) SetSsiModInfo(uin string, modDate uint32, itemCount uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Exec("UPDATE users SET ssi_mod_date=?, ssi_item_count=? WHERE uin=?", modDate, itemCount, uin)
}

func (s *Storage) TouchSsiMod(uin string) (uint32, uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var nGroups, nContacts, nPrivacy int
	s.db.QueryRow("SELECT COUNT(*) FROM groups_tbl WHERE uin=?", uin).Scan(&nGroups)
	s.db.QueryRow("SELECT COUNT(*) FROM contacts WHERE uin=?", uin).Scan(&nContacts)
	s.db.QueryRow("SELECT COUNT(*) FROM privacy_items WHERE uin=?", uin).Scan(&nPrivacy)
	var pdMode sql.NullInt64
	s.db.QueryRow("SELECT pd_mode FROM privacy_mode WHERE uin=?", uin).Scan(&pdMode)
	nPD := 0
	if pdMode.Valid && int(pdMode.Int64) != PDModePermitAll {
		nPD = 1
	}
	itemCount := uint16(nGroups + nContacts + nPrivacy + nPD)
	modDate := uint32(time.Now().Unix())
	s.db.Exec("UPDATE users SET ssi_mod_date=?, ssi_item_count=? WHERE uin=?", modDate, itemCount, uin)
	return modDate, itemCount
}

func (s *Storage) UpsertMiscItem(uin string, groupID, itemID, itemType uint16, name string, tlvData []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Exec(`INSERT INTO misc_ssi_items (uin, group_id, item_id, item_type, name, tlv_data)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(uin, group_id, item_id, item_type) DO UPDATE SET
			name=excluded.name, tlv_data=excluded.tlv_data`,
		uin, groupID, itemID, itemType, name, tlvData)
}

func (s *Storage) DeleteMiscItem(uin string, groupID, itemID, itemType uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Exec("DELETE FROM misc_ssi_items WHERE uin=? AND group_id=? AND item_id=? AND item_type=?",
		uin, groupID, itemID, itemType)
}

func (s *Storage) FixOrphanContacts(uin string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query("SELECT group_id FROM groups_tbl WHERE uin=?", uin)
	if err != nil {
		return false
	}
	valid := map[uint16]bool{}
	for rows.Next() {
		var gid uint16
		rows.Scan(&gid)
		valid[gid] = true
	}
	rows.Close()

	crows, err := s.db.Query("SELECT contact_uin, group_id FROM contacts WHERE uin=?", uin)
	if err != nil {
		return false
	}
	var orphans []string
	for crows.Next() {
		var cuin string
		var gid uint16
		crows.Scan(&cuin, &gid)
		if !valid[gid] {
			orphans = append(orphans, cuin)
		}
	}
	crows.Close()
	if len(orphans) == 0 {
		return false
	}
	var target uint16
	var namedGid sql.NullInt64
	err = s.db.QueryRow("SELECT group_id FROM groups_tbl WHERE uin=? AND name != '' ORDER BY group_id LIMIT 1", uin).Scan(&namedGid)
	if err == nil && namedGid.Valid {
		target = uint16(namedGid.Int64)
	} else {
		s.db.Exec("INSERT OR IGNORE INTO groups_tbl (uin, group_id, name) VALUES (?, ?, ?)",
			uin, SsiGeneralGroupID, SsiGeneralGroupName)
		target = SsiGeneralGroupID
	}
	for _, c := range orphans {
		s.db.Exec("UPDATE contacts SET group_id=? WHERE uin=? AND contact_uin=?", target, uin, c)
	}
	return true
}

func (s *Storage) SetGroupItems(uin string, groupID uint16, itemIDs []uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Exec("DELETE FROM group_items WHERE uin=? AND group_id=?", uin, groupID)
	for pos, iid := range itemIDs {
		s.db.Exec("INSERT INTO group_items (uin, group_id, item_id, position) VALUES (?, ?, ?, ?)",
			uin, groupID, iid, pos)
	}
}

func (s *Storage) AddGroupItem(uin string, groupID, itemID uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var pos int
	s.db.QueryRow("SELECT COALESCE(MAX(position),-1)+1 FROM group_items WHERE uin=? AND group_id=?", uin, groupID).Scan(&pos)
	s.db.Exec("INSERT OR IGNORE INTO group_items (uin, group_id, item_id, position) VALUES (?, ?, ?, ?)",
		uin, groupID, itemID, pos)
}

func (s *Storage) RemoveGroupItem(uin string, groupID, itemID uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Exec("DELETE FROM group_items WHERE uin=? AND group_id=? AND item_id=?", uin, groupID, itemID)
}

func (s *Storage) UpsertContact(uin, contactUin string, groupID, itemID uint16, nick string, pendingAuth bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Exec(`INSERT INTO contacts (uin, contact_uin, group_id, item_id, nick, pending_auth)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(uin, contact_uin) DO UPDATE SET
			group_id=excluded.group_id, item_id=excluded.item_id,
			nick=excluded.nick, pending_auth=excluded.pending_auth`,
		uin, contactUin, groupID, itemID, nick, boolToInt(pendingAuth))
}

func (s *Storage) DeleteContact(uin, contactUin string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Exec("DELETE FROM contacts WHERE uin=? AND contact_uin=?", uin, contactUin)
}

func (s *Storage) ClearPendingAuth(uin, contactUin string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec("UPDATE contacts SET pending_auth=0 WHERE uin=? AND contact_uin=? AND pending_auth=1", uin, contactUin)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

func (s *Storage) UpsertPrivacyItem(uin string, itemType int, targetUin string, itemID uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Exec(`INSERT INTO privacy_items (uin, item_type, target_uin, item_id) VALUES (?, ?, ?, ?)
		ON CONFLICT(uin, item_type, target_uin) DO UPDATE SET item_id=excluded.item_id`,
		uin, itemType, targetUin, itemID)
}

func (s *Storage) DeletePrivacyItem(uin string, itemType int, targetUin string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Exec("DELETE FROM privacy_items WHERE uin=? AND item_type=? AND target_uin=?", uin, itemType, targetUin)
}

func (s *Storage) SetPDMode(uin string, mode int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Exec(`INSERT INTO privacy_mode (uin, pd_mode) VALUES (?, ?)
		ON CONFLICT(uin) DO UPDATE SET pd_mode=excluded.pd_mode`, uin, mode)
}

func (s *Storage) AddOfflineMsg(toUin, fromUin, text string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var one int
	if err := s.db.QueryRow("SELECT 1 FROM users WHERE uin=?", toUin).Scan(&one); err != nil {
		return
	}
	s.db.Exec("INSERT INTO offline_messages (to_uin, from_uin, text, timestamp, msg_type) VALUES (?, ?, ?, ?, ?)",
		toUin, fromUin, text, float64(time.Now().UnixNano())/1e9, 1)
}

func (s *Storage) GetOfflineMsgs(uin string) []OfflineMessage {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query("SELECT from_uin, text, timestamp, msg_type FROM offline_messages WHERE to_uin=? ORDER BY id", uin)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []OfflineMessage
	for rows.Next() {
		var m OfflineMessage
		rows.Scan(&m.FromUIN, &m.Text, &m.Timestamp, &m.MsgType)
		out = append(out, m)
	}
	return out
}

func (s *Storage) ClearOfflineMsgs(uin string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Exec("DELETE FROM offline_messages WHERE to_uin=?", uin)
}

func (s *Storage) AddPendingAuthRequest(toUin, fromUin, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var one int
	if err := s.db.QueryRow("SELECT 1 FROM users WHERE uin=?", toUin).Scan(&one); err != nil {
		return
	}
	s.db.Exec("INSERT OR REPLACE INTO pending_auth_requests (to_uin, from_uin, reason, timestamp) VALUES (?, ?, ?, ?)",
		toUin, fromUin, reason, float64(time.Now().UnixNano())/1e9)
}

func (s *Storage) GetPendingAuthRequests(uin string) []PendingAuthRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query("SELECT from_uin, reason, timestamp FROM pending_auth_requests WHERE to_uin=? ORDER BY timestamp", uin)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []PendingAuthRequest
	for rows.Next() {
		var r PendingAuthRequest
		rows.Scan(&r.FromUIN, &r.Reason, &r.Timestamp)
		out = append(out, r)
	}
	return out
}

func (s *Storage) ClearPendingAuthRequests(uin string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Exec("DELETE FROM pending_auth_requests WHERE to_uin=?", uin)
}

func (s *Storage) SearchUsers(c SearchCriteria, onlineUins map[string]bool) []SearchResult {
	var clauses []string
	var params []interface{}
	if c.UIN != "" {
		clauses = append(clauses, "u.uin LIKE ?")
		params = append(params, "%"+c.UIN+"%")
	}
	if c.Nick != "" {
		clauses = append(clauses, "LOWER(p.nick) LIKE ?")
		params = append(params, "%"+strings.ToLower(c.Nick)+"%")
	}
	if c.FirstName != "" {
		clauses = append(clauses, "LOWER(p.first_name) LIKE ?")
		params = append(params, "%"+strings.ToLower(c.FirstName)+"%")
	}
	if c.LastName != "" {
		clauses = append(clauses, "LOWER(p.last_name) LIKE ?")
		params = append(params, "%"+strings.ToLower(c.LastName)+"%")
	}
	if c.Email != "" {
		clauses = append(clauses, "LOWER(p.email) LIKE ?")
		params = append(params, "%"+strings.ToLower(c.Email)+"%")
	}
	if c.City != "" {
		clauses = append(clauses, "LOWER(p.city) LIKE ?")
		params = append(params, "%"+strings.ToLower(c.City)+"%")
	}
	if c.Keyword != "" {
		clauses = append(clauses, "LOWER(p.about) LIKE ?")
		params = append(params, "%"+strings.ToLower(c.Keyword)+"%")
	}
	where := ""
	if len(clauses) > 0 {
		where = "WHERE " + strings.Join(clauses, " AND ")
	}
	query := fmt.Sprintf(`SELECT u.uin, p.nick, p.first_name, p.last_name, p.email, p.auth_required,
		p.gender, p.age FROM users u JOIN profiles p ON p.uin=u.uin %s LIMIT 1000`, where)

	s.mu.Lock()
	rows, err := s.db.Query(query, params...)
	s.mu.Unlock()
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []SearchResult
	for rows.Next() {
		if len(out) >= 100 {
			break
		}
		var r SearchResult
		var authReq int
		var age int
		rows.Scan(&r.UIN, &r.Nick, &r.FirstName, &r.LastName, &r.Email, &authReq, &r.Gender, &age)
		r.AuthReq = authReq != 0
		r.Age = age
		if c.OnlyOnline && !onlineUins[r.UIN] {
			continue
		}
		r.Online = onlineUins[r.UIN]
		out = append(out, r)
	}
	return out
}
