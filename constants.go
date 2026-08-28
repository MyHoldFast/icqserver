package main

import "path/filepath"

const (
	ServerHost = "0.0.0.0"
	ServerPort = 5190
)

var DBPath = func() string {
	p, _ := filepath.Abs("icq_server.db")
	return p
}()

const (
	StatusOnline  uint32 = 0x00000000
	StatusAway    uint32 = 0x00000001
	StatusDND     uint32 = 0x00000002
	StatusNA      uint32 = 0x00000004
	StatusFree    uint32 = 0x00000020
	StatusOffline uint32 = 0xFFFFFFFF
)

const (
	CliMetaReqMoreInfoType  = 0x04B2
	CliMetaReqHomeInfoType  = 0x04D0
	CliMetaReqShortInfoType = 0x04BA
	MetaInfoShort           = 0x0104
	MetaFail                = 0x14
	CliSetFullInfoType      = 0x0C3A
	SrvMetaGeneralType      = 0x00C8
	SrvMetaMoreType         = 0x00DC
	SrvMetaWorkType         = 0x00D2
	SrvMetaAboutType        = 0x00E6
	MetaInfoEmailMore       = 0x00EB
	MetaInfoHpageCat        = 0x010E
	MetaInfoInterests       = 0x00F0
	MetaInfoAffilations     = 0x00FA
	MetaInfoSetPassword     = 0x042E
	MetaInfoPassAck         = 0x00AA
	MetaInfoSetPerms        = 0x0424
	MetaInfoPermsAck        = 0x00A0
	CliMetaSrvxmlReq        = 0x0898
	SrvMetaSrvxmlRsp        = 0x08A2
)

const (
	CliRosterAddCmd    = 0x0008
	CliRosterDeleteCmd = 0x000A
	SrvUpdateAckCmd    = 0x000E

	SsiUpdateSuccess      = 0x0000
	SsiUpdateNotFound     = 0x0002
	SsiUpdateError        = 0x000A
	SsiUpdateLimit        = 0x000C
	SsiUpdateAuthRequired = 0x000E

	CliAddStartCmd     = 0x0011
	CliAddEndCmd       = 0x0012
	CliRosterUpdateCmd = 0x0009

	MetaReqOfflineMsg  = 0x003C
	MetaAckOfflineMsg  = 0x003E
	OfflineMsgResponse = 0x0041
	OfflineMsgEOF      = 0x0042
)

const (
	SsiItemBuddy  = 0x0000
	SsiItemGroup  = 0x0001
	SsiItemPermit = 0x0002
	SsiItemDeny   = 0x0003
	SsiItemPDInfo = 0x0004
	TlvPDMode     = 0x00CA

	PDModePermitAll     = 1
	PDModeDenyAll       = 2
	PDModePermitSome    = 3
	PDModeDenySome      = 4
	PDModePermitBuddies = 5
)

const (
	SsiAuthSendReq   = 0x0018
	SsiAuthReq       = 0x0019
	SsiAuthSendReply = 0x001A
	SsiAuthReply     = 0x001B
	SsiYouWereAdded  = 0x001C
	SsiDelYourself   = 0x0016
)

const (
	SaveTlvNick      = 0x0154
	SaveTlvFirstName = 0x0140
	SaveTlvLastName  = 0x014A
	SaveTlvEmail     = 0x015E
	SaveTlvBday      = 0x023A
	SaveTlvCity      = 0x0190
	SaveTlvHomePage  = 0x0213
	SaveTlvAbout     = 0x0258
	SaveTlvGender    = 0x017C
	SaveTlvAuth      = 0x030C
	SaveTlvAuth2     = 0x02F8
)

const (
	SearchTlvUin        = 0x0136
	SearchTlvNick       = SaveTlvNick
	SearchTlvFirstName  = SaveTlvFirstName
	SearchTlvLastName   = SaveTlvLastName
	SearchTlvEmail      = SaveTlvEmail
	SearchTlvCity       = SaveTlvCity
	SearchTlvOnlyOnline = 0x0230

	SrvSearchFound     = 0x01A4
	SrvSearchLast      = 0x01AE
	MetaSuccess        = 0x0A
	MetaEmpty          = 0x32
	MetaInfoSearchResp = 0x0FB4
)

type famVer struct {
	Fam uint16
	Ver uint16
}

var ServerFamilies = []famVer{
	{0x0001, 0x0003},
	{0x0002, 0x0001},
	{0x0003, 0x0001},
	{0x0004, 0x0001},
	{0x0006, 0x0001},
	{0x0007, 0x0001},
	{0x0008, 0x0001},
	{0x0009, 0x0001},
	{0x000A, 0x0001},
	{0x000B, 0x0001},
	{0x000C, 0x0001},
	{0x0013, 0x0004},
	{0x0015, 0x0001},
}

var ServerFamilyIDs = func() []uint16 {
	ids := make([]uint16, len(ServerFamilies))
	for i, fv := range ServerFamilies {
		ids[i] = fv.Fam
	}
	return ids
}()

const (
	SnTypRegistration = 0x0017
	SnIesError        = 0x0001
	SnIesAuthLogin    = 0x0002
	SnIesAuthRequest  = 0x0006
	SnIesAuthKey      = 0x0007
	SnIesLoginReply   = 0x0003
	SnIesReqNewUin    = 0x0004
	SnIesSrvNewUin    = 0x0005
)

var AimMD5String = []byte("AOL Instant Messenger (SM)")

const NewUinFloor = 1001

const (
	SsiMasterGroupID  uint16 = 0
	SsiGeneralGroupID uint16 = 1
)

const ConnIdleTimeoutSec = 360
const SsiGeneralGroupName = "General"

const (
	IcbmFlgBase     uint32 = 0x00000001
	IcbmFlgMissed   uint32 = 0x00000002
	IcbmFlgMtn      uint32 = 0x00000008
	MaxIcbmChannels uint16 = 4
)

func defaultIcbmFlags() map[uint16]uint32 {
	f := IcbmFlgBase | IcbmFlgMissed
	return map[uint16]uint32{1: f, 2: f, 4: f}
}
