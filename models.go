package main

type ContactEntry struct {
	UIN         string
	GroupID     uint16
	ItemID      uint16
	Nick        string
	PendingAuth bool
}

type GroupEntry struct {
	GroupID uint16
	Name    string
	ItemIDs []uint16
}

type OfflineMessage struct {
	FromUIN   string
	Text      string
	Timestamp float64
	MsgType   uint16
}

type PendingAuthRequest struct {
	FromUIN   string
	Reason    string
	Timestamp float64
}

type UserProfile struct {
	Nick         string
	FirstName    string
	LastName     string
	Email        string
	City         string
	State        string
	Phone        string
	Fax          string
	Address      string
	CellPhone    string
	Age          uint16
	Gender       string
	HomePage     string
	Birthday     string
	About        string
	WorkCity     string
	WorkState    string
	WorkPhone    string
	WorkFax      string
	WorkAddr     string
	WorkName     string
	WorkDep      string
	WorkPos      string
	AuthRequired bool
}

type MiscSSIKey struct {
	GroupID  uint16
	ItemID   uint16
	ItemType uint16
}

type MiscSsiItem struct {
	Name     string
	GroupID  uint16
	ItemID   uint16
	ItemType uint16
	TlvData  []byte
}

type UserAccount struct {
	UIN          string
	Password     string
	Profile      UserProfile
	Contacts     map[string]*ContactEntry
	Groups       map[uint16]*GroupEntry
	GroupOrder   []uint16
	NextItemID   int
	Permit       map[string]uint16
	Deny         map[string]uint16
	PDMode       int
	MiscItems    map[MiscSSIKey]*MiscSsiItem
	SsiModDate   uint32
	SsiItemCount uint16
}

func newUserAccount(uin string) *UserAccount {
	return &UserAccount{
		UIN:        uin,
		Contacts:   map[string]*ContactEntry{},
		Groups:     map[uint16]*GroupEntry{},
		Permit:     map[string]uint16{},
		Deny:       map[string]uint16{},
		PDMode:     PDModePermitAll,
		NextItemID: 1,
		MiscItems:  map[MiscSSIKey]*MiscSsiItem{},
	}
}

type SearchResult struct {
	UIN       string
	Nick      string
	FirstName string
	LastName  string
	Email     string
	AuthReq   bool
	Online    bool
	Gender    string
	Age       int
}

type SearchCriteria struct {
	UIN        string
	Nick       string
	FirstName  string
	LastName   string
	Email      string
	City       string
	Keyword    string
	OnlyOnline bool
}
