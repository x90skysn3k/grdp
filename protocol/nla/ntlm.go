package nla

import (
	"bytes"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/lunixbochs/struc"
	"github.com/x90skysn3k/grdp/core"
	"github.com/x90skysn3k/grdp/glog"
)

const (
	WINDOWS_MINOR_VERSION_0 = 0x00
	WINDOWS_MINOR_VERSION_1 = 0x01
	WINDOWS_MINOR_VERSION_2 = 0x02
	WINDOWS_MINOR_VERSION_3 = 0x03

	WINDOWS_MAJOR_VERSION_5 = 0x05
	WINDOWS_MAJOR_VERSION_6 = 0x06
	NTLMSSP_REVISION_W2K3   = 0x0F
)

const (
	MsvAvEOL             = 0x0000
	MsvAvNbComputerName  = 0x0001
	MsvAvNbDomainName    = 0x0002
	MsvAvDnsComputerName = 0x0003
	MsvAvDnsDomainName   = 0x0004
	MsvAvDnsTreeName     = 0x0005
	MsvAvFlags           = 0x0006
	MsvAvTimestamp       = 0x0007
	MsvAvSingleHost      = 0x0008
	MsvAvTargetName      = 0x0009
	MsvChannelBindings   = 0x000A
)

type AVPair struct {
	Id    uint16 `struc:"little"`
	Len   uint16 `struc:"little,sizeof=Value"`
	Value []byte `struc:"little"`
}

const (
	NTLMSSP_NEGOTIATE_56                       = 0x80000000
	NTLMSSP_NEGOTIATE_KEY_EXCH                 = 0x40000000
	NTLMSSP_NEGOTIATE_128                      = 0x20000000
	NTLMSSP_NEGOTIATE_VERSION                  = 0x02000000
	NTLMSSP_NEGOTIATE_TARGET_INFO              = 0x00800000
	NTLMSSP_REQUEST_NON_NT_SESSION_KEY         = 0x00400000
	NTLMSSP_NEGOTIATE_IDENTIFY                 = 0x00100000
	NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x00080000
	NTLMSSP_TARGET_TYPE_SERVER                 = 0x00020000
	NTLMSSP_TARGET_TYPE_DOMAIN                 = 0x00010000
	NTLMSSP_NEGOTIATE_ALWAYS_SIGN              = 0x00008000
	NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 0x00002000
	NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED      = 0x00001000
	NTLMSSP_NEGOTIATE_NTLM                     = 0x00000200
	NTLMSSP_NEGOTIATE_LM_KEY                   = 0x00000080
	NTLMSSP_NEGOTIATE_DATAGRAM                 = 0x00000040
	NTLMSSP_NEGOTIATE_SEAL                     = 0x00000020
	NTLMSSP_NEGOTIATE_SIGN                     = 0x00000010
	NTLMSSP_REQUEST_TARGET                     = 0x00000004
	NTLM_NEGOTIATE_OEM                         = 0x00000002
	NTLMSSP_NEGOTIATE_UNICODE                  = 0x00000001
)

type NVersion struct {
	ProductMajorVersion uint8   `struc:"little"`
	ProductMinorVersion uint8   `struc:"little"`
	ProductBuild        uint16  `struc:"little"`
	Reserved            [3]byte `struc:"little"`
	NTLMRevisionCurrent uint8   `struc:"little"`
}

func NewNVersion() NVersion {
	return NVersion{
		ProductMajorVersion: WINDOWS_MAJOR_VERSION_6,
		ProductMinorVersion: WINDOWS_MINOR_VERSION_0,
		ProductBuild:        6002,
		NTLMRevisionCurrent: NTLMSSP_REVISION_W2K3,
	}
}

type Message interface {
	Serialize() []byte
}

type NegotiateMessage struct {
	Signature               [8]byte  `struc:"little"`
	MessageType             uint32   `struc:"little"`
	NegotiateFlags          uint32   `struc:"little"`
	DomainNameLen           uint16   `struc:"little"`
	DomainNameMaxLen        uint16   `struc:"little"`
	DomainNameBufferOffset  uint32   `struc:"little"`
	WorkstationLen          uint16   `struc:"little"`
	WorkstationMaxLen       uint16   `struc:"little"`
	WorkstationBufferOffset uint32   `struc:"little"`
	Version                 NVersion `struc:"little"`
	Payload                 [32]byte `struc:"skip"`
}

func NewNegotiateMessage() *NegotiateMessage {
	return &NegotiateMessage{
		Signature:   [8]byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00},
		MessageType: 0x00000001,
	}
}

func (m *NegotiateMessage) Serialize() []byte {
	if (m.NegotiateFlags & NTLMSSP_NEGOTIATE_VERSION) != 0 {
		m.Version = NewNVersion()
	}
	buff := &bytes.Buffer{}
	struc.Pack(buff, m)

	return buff.Bytes()
}

type ChallengeMessage struct {
	Signature              []byte   `struc:"[8]byte"`
	MessageType            uint32   `struc:"little"`
	TargetNameLen          uint16   `struc:"little"`
	TargetNameMaxLen       uint16   `struc:"little"`
	TargetNameBufferOffset uint32   `struc:"little"`
	NegotiateFlags         uint32   `struc:"little"`
	ServerChallenge        [8]byte  `struc:"little"`
	Reserved               [8]byte  `struc:"little"`
	TargetInfoLen          uint16   `struc:"little"`
	TargetInfoMaxLen       uint16   `struc:"little"`
	TargetInfoBufferOffset uint32   `struc:"little"`
	Version                NVersion `struc:"skip"`
	Payload                []byte   `struc:"skip"`
}

func (m *ChallengeMessage) Serialize() []byte {
	buff := &bytes.Buffer{}
	struc.Pack(buff, m)
	if (m.NegotiateFlags & NTLMSSP_NEGOTIATE_VERSION) != 0 {
		struc.Pack(buff, m.Version)
	}
	buff.Write(m.Payload)
	return buff.Bytes()
}

func NewChallengeMessage() *ChallengeMessage {
	return &ChallengeMessage{
		Signature:   []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00},
		MessageType: 0x00000002,
	}
}

// BaseLen returns the fixed header size, including the optional VERSION field.
func (m *ChallengeMessage) BaseLen() uint32 {
	if m.NegotiateFlags&NTLMSSP_NEGOTIATE_VERSION != 0 {
		return 56
	}
	return 48
}

func (m *ChallengeMessage) getTargetInfo() []byte {
	if m.TargetInfoLen == 0 {
		return nil
	}
	start := uint64(m.TargetInfoBufferOffset) - uint64(m.BaseLen())
	return m.Payload[start : start+uint64(m.TargetInfoLen)]
}
func (m *ChallengeMessage) getTargetName() []byte {
	if m.TargetNameLen == 0 {
		return nil
	}
	start := uint64(m.TargetNameBufferOffset) - uint64(m.BaseLen())
	return m.Payload[start : start+uint64(m.TargetNameLen)]
}

// parseChallenge validates wire offsets before any unsigned subtraction or slice.
func parseChallenge(data []byte) (*ChallengeMessage, error) {
	if len(data) < 48 {
		return nil, fmt.Errorf("NTLM challenge header truncated")
	}
	if string(data[:8]) != "NTLMSSP\x00" || binary.LittleEndian.Uint32(data[8:12]) != 2 {
		return nil, fmt.Errorf("invalid NTLM challenge signature or message type")
	}
	m := &ChallengeMessage{}
	r := bytes.NewReader(data)
	if err := struc.Unpack(r, m); err != nil {
		return nil, fmt.Errorf("decode NTLM challenge: %w", err)
	}
	header := m.BaseLen()
	if uint64(len(data)) < uint64(header) {
		return nil, fmt.Errorf("NTLM challenge version truncated")
	}
	if m.NegotiateFlags&NTLMSSP_NEGOTIATE_VERSION != 0 {
		if err := struc.Unpack(r, &m.Version); err != nil {
			return nil, fmt.Errorf("decode NTLM challenge version: %w", err)
		}
	}
	for _, field := range []struct {
		length uint16
		offset uint32
	}{
		{m.TargetNameLen, m.TargetNameBufferOffset},
		{m.TargetInfoLen, m.TargetInfoBufferOffset},
	} {
		// MS-NLMP: offsets and MaxLen are ignored for an empty buffer.
		if field.length == 0 {
			continue
		}
		if field.offset < header || uint64(field.offset)+uint64(field.length) > uint64(len(data)) {
			return nil, fmt.Errorf("NTLM challenge security buffer outside payload")
		}
	}
	if m.NegotiateFlags&NTLMSSP_NEGOTIATE_UNICODE != 0 && m.TargetNameLen%2 != 0 {
		return nil, fmt.Errorf("invalid NTLM Unicode target name length")
	}
	m.Payload = data[header:]
	return m, nil
}

// TargetInfo is a bounded AV_PAIR list, terminated by a zero-length MsvAvEOL.
// Decode lengths directly rather than letting struc allocate from untrusted input.
func (m *ChallengeMessage) getTargetInfoTimestamp(data []byte) ([]byte, error) {
	var timestamp []byte
	if len(data) == 0 {
		return nil, nil
	}
	for len(data) > 0 {
		if len(data) < 4 {
			return nil, fmt.Errorf("NTLM target info AV header truncated")
		}
		id := binary.LittleEndian.Uint16(data[:2])
		length := int(binary.LittleEndian.Uint16(data[2:4]))
		data = data[4:]
		if length > len(data) {
			return nil, fmt.Errorf("NTLM target info AV value truncated")
		}
		switch id {
		case MsvAvEOL:
			if length != 0 || len(data) != 0 {
				return nil, fmt.Errorf("invalid NTLM target info terminator")
			}
			return timestamp, nil
		case MsvAvTimestamp:
			if length != 8 {
				return nil, fmt.Errorf("invalid NTLM timestamp length")
			}
			timestamp = data[:length]
		case MsvAvFlags:
			if length != 4 {
				return nil, fmt.Errorf("invalid NTLM AV flags length")
			}
		case MsvAvSingleHost:
			if length != 48 {
				return nil, fmt.Errorf("invalid NTLM single-host length")
			}
		case MsvChannelBindings:
			if length != 16 {
				return nil, fmt.Errorf("invalid NTLM channel bindings length")
			}
		case MsvAvNbComputerName, MsvAvNbDomainName, MsvAvDnsComputerName,
			MsvAvDnsDomainName, MsvAvDnsTreeName, MsvAvTargetName:
			if length%2 != 0 {
				return nil, fmt.Errorf("invalid NTLM Unicode AV length")
			}
		}
		data = data[length:]
	}
	return nil, fmt.Errorf("NTLM target info missing terminator")
}

type AuthenticateMessage struct {
	Signature                          [8]byte
	MessageType                        uint32   `struc:"little"`
	LmChallengeResponseLen             uint16   `struc:"little"`
	LmChallengeResponseMaxLen          uint16   `struc:"little"`
	LmChallengeResponseBufferOffset    uint32   `struc:"little"`
	NtChallengeResponseLen             uint16   `struc:"little"`
	NtChallengeResponseMaxLen          uint16   `struc:"little"`
	NtChallengeResponseBufferOffset    uint32   `struc:"little"`
	DomainNameLen                      uint16   `struc:"little"`
	DomainNameMaxLen                   uint16   `struc:"little"`
	DomainNameBufferOffset             uint32   `struc:"little"`
	UserNameLen                        uint16   `struc:"little"`
	UserNameMaxLen                     uint16   `struc:"little"`
	UserNameBufferOffset               uint32   `struc:"little"`
	WorkstationLen                     uint16   `struc:"little"`
	WorkstationMaxLen                  uint16   `struc:"little"`
	WorkstationBufferOffset            uint32   `struc:"little"`
	EncryptedRandomSessionLen          uint16   `struc:"little"`
	EncryptedRandomSessionMaxLen       uint16   `struc:"little"`
	EncryptedRandomSessionBufferOffset uint32   `struc:"little"`
	NegotiateFlags                     uint32   `struc:"little"`
	Version                            NVersion `struc:"little"`
	MIC                                [16]byte `struc:"little"`
	Payload                            []byte   `struc:"skip"`
}

func (m *AuthenticateMessage) BaseLen() uint32 {
	return 88
}

func NewAuthenticateMessage(negFlag uint32, domain, user, workstation []byte,
	lmchallResp, ntchallResp, enRandomSessKey []byte) *AuthenticateMessage {
	msg := &AuthenticateMessage{
		Signature:      [8]byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00},
		MessageType:    0x00000003,
		NegotiateFlags: negFlag,
	}
	payloadBuff := &bytes.Buffer{}

	msg.LmChallengeResponseLen = uint16(len(lmchallResp))
	msg.LmChallengeResponseMaxLen = msg.LmChallengeResponseLen
	msg.LmChallengeResponseBufferOffset = msg.BaseLen()
	payloadBuff.Write(lmchallResp)

	msg.NtChallengeResponseLen = uint16(len(ntchallResp))
	msg.NtChallengeResponseMaxLen = msg.NtChallengeResponseLen
	msg.NtChallengeResponseBufferOffset = msg.LmChallengeResponseBufferOffset + uint32(msg.LmChallengeResponseLen)
	payloadBuff.Write(ntchallResp)

	msg.DomainNameLen = uint16(len(domain))
	msg.DomainNameMaxLen = msg.DomainNameLen
	msg.DomainNameBufferOffset = msg.NtChallengeResponseBufferOffset + uint32(msg.NtChallengeResponseLen)
	payloadBuff.Write(domain)

	msg.UserNameLen = uint16(len(user))
	msg.UserNameMaxLen = msg.UserNameLen
	msg.UserNameBufferOffset = msg.DomainNameBufferOffset + uint32(msg.DomainNameLen)
	payloadBuff.Write(user)

	msg.WorkstationLen = uint16(len(workstation))
	msg.WorkstationMaxLen = msg.WorkstationLen
	msg.WorkstationBufferOffset = msg.UserNameBufferOffset + uint32(msg.UserNameLen)
	payloadBuff.Write(workstation)

	msg.EncryptedRandomSessionLen = uint16(len(enRandomSessKey))
	msg.EncryptedRandomSessionMaxLen = msg.EncryptedRandomSessionLen
	msg.EncryptedRandomSessionBufferOffset = msg.WorkstationBufferOffset + uint32(msg.WorkstationLen)
	payloadBuff.Write(enRandomSessKey)

	if (msg.NegotiateFlags & NTLMSSP_NEGOTIATE_VERSION) != 0 {
		msg.Version = NewNVersion()
	}
	msg.Payload = payloadBuff.Bytes()

	return msg
}

func (m *AuthenticateMessage) Serialize() []byte {
	buff := &bytes.Buffer{}
	struc.Pack(buff, m)
	buff.Write(m.Payload)
	return buff.Bytes()
}

type NTLMv2 struct {
	domain              string
	user                string
	password            string
	respKeyNT           []byte
	respKeyLM           []byte
	negotiateMessage    *NegotiateMessage
	challengeMessage    *ChallengeMessage
	authenticateMessage *AuthenticateMessage
	enableUnicode       bool
}

func NewNTLMv2(domain, user, password string) *NTLMv2 {
	return &NTLMv2{
		domain:    domain,
		user:      user,
		password:  password,
		respKeyNT: NTOWFv2(password, user, domain),
		respKeyLM: LMOWFv2(password, user, domain),
	}
}

// generate first handshake messgae
func (n *NTLMv2) GetNegotiateMessage() *NegotiateMessage {
	negoMsg := NewNegotiateMessage()
	negoMsg.NegotiateFlags = NTLMSSP_NEGOTIATE_KEY_EXCH |
		NTLMSSP_NEGOTIATE_128 |
		NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
		NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
		NTLMSSP_NEGOTIATE_NTLM |
		NTLMSSP_NEGOTIATE_SEAL |
		NTLMSSP_NEGOTIATE_SIGN |
		NTLMSSP_REQUEST_TARGET |
		NTLMSSP_NEGOTIATE_UNICODE
	n.negotiateMessage = negoMsg
	return n.negotiateMessage
}

// process NTLMv2 Authenticate hash
func (n *NTLMv2) ComputeResponseV2(respKeyNT, respKeyLM, serverChallenge, clientChallenge,
	timestamp, serverInfo []byte) (ntChallResp, lmChallResp, SessBaseKey []byte) {

	tempBuff := &bytes.Buffer{}
	tempBuff.Write([]byte{0x01, 0x01}) // Responser version, HiResponser version
	tempBuff.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	tempBuff.Write(timestamp)
	tempBuff.Write(clientChallenge)
	tempBuff.Write([]byte{0x00, 0x00, 0x00, 0x00})
	tempBuff.Write(serverInfo)
	tempBuff.Write([]byte{0x00, 0x00, 0x00, 0x00})

	ntBuf := bytes.NewBuffer(serverChallenge)
	ntBuf.Write(tempBuff.Bytes())
	ntProof := HMAC_MD5(respKeyNT, ntBuf.Bytes())

	ntChallResp = make([]byte, 0, len(ntProof)+tempBuff.Len())
	ntChallResp = append(ntChallResp, ntProof...)
	ntChallResp = append(ntChallResp, tempBuff.Bytes()...)

	lmBuf := bytes.NewBuffer(serverChallenge)
	lmBuf.Write(clientChallenge)
	lmChallResp = HMAC_MD5(respKeyLM, lmBuf.Bytes())
	lmChallResp = append(lmChallResp, clientChallenge...)

	SessBaseKey = HMAC_MD5(respKeyNT, ntProof)
	return
}

func MIC(exportedSessionKey []byte, negotiateMessage, challengeMessage, authenticateMessage Message) []byte {
	buff := bytes.Buffer{}
	buff.Write(negotiateMessage.Serialize())
	buff.Write(challengeMessage.Serialize())
	buff.Write(authenticateMessage.Serialize())
	return HMAC_MD5(exportedSessionKey, buff.Bytes())
}

func concat(bs ...[]byte) []byte {
	return bytes.Join(bs, nil)
}

var (
	clientSigning = concat([]byte("session key to client-to-server signing key magic constant"), []byte{0x00})
	serverSigning = concat([]byte("session key to server-to-client signing key magic constant"), []byte{0x00})
	clientSealing = concat([]byte("session key to client-to-server sealing key magic constant"), []byte{0x00})
	serverSealing = concat([]byte("session key to server-to-client sealing key magic constant"), []byte{0x00})
)

// GetAuthenticateMessage returns nil, nil for an invalid server challenge.
func (n *NTLMv2) GetAuthenticateMessage(s []byte) (*AuthenticateMessage, *NTLMv2Security) {
	challengeMsg, err := parseChallenge(s)
	if err != nil {
		glog.Error("read challengeMsg", err)
		return nil, nil
	}
	n.challengeMessage = challengeMsg
	glog.Debugf("challengeMsg:%+v", challengeMsg)

	serverName := challengeMsg.getTargetName()
	serverInfo := challengeMsg.getTargetInfo()
	timestamp, err := challengeMsg.getTargetInfoTimestamp(serverInfo)
	if err != nil {
		glog.Error("read target info", err)
		return nil, nil
	}
	computeMIC := false
	if timestamp == nil {
		ft := uint64(time.Now().UnixNano()) / 100
		ft += 116444736000000000 // add time between unix & windows offset
		timestamp = make([]byte, 8)
		binary.LittleEndian.PutUint64(timestamp, ft)
	} else {
		computeMIC = true
	}
	glog.Infof("serverName=%+v", core.UnicodeDecode(serverName))
	serverChallenge := challengeMsg.ServerChallenge[:]
	clientChallenge := core.Random(8)
	ntChallengeResponse, lmChallengeResponse, SessionBaseKey := n.ComputeResponseV2(
		n.respKeyNT, n.respKeyLM, serverChallenge, clientChallenge, timestamp, serverInfo)

	exchangeKey := SessionBaseKey
	exportedSessionKey := core.Random(16)
	EncryptedRandomSessionKey := make([]byte, len(exportedSessionKey))
	rc, _ := rc4.NewCipher(exchangeKey)
	rc.XORKeyStream(EncryptedRandomSessionKey, exportedSessionKey)

	if challengeMsg.NegotiateFlags&NTLMSSP_NEGOTIATE_UNICODE != 0 {
		n.enableUnicode = true
	}
	glog.Infof("user: %s, passwd:%s", n.user, n.password)
	domain, user, _ := n.GetEncodedCredentials()

	n.authenticateMessage = NewAuthenticateMessage(challengeMsg.NegotiateFlags,
		domain, user, []byte(""), lmChallengeResponse, ntChallengeResponse, EncryptedRandomSessionKey)

	if computeMIC {
		if n.negotiateMessage == nil {
			n.GetNegotiateMessage()
		}
		copy(n.authenticateMessage.MIC[:], MIC(exportedSessionKey, n.negotiateMessage, n.challengeMessage, n.authenticateMessage)[:16])
	}

	md := md5.New()
	//ClientSigningKey
	a := concat(exportedSessionKey, clientSigning)
	md.Write(a)
	ClientSigningKey := md.Sum(nil)
	//ServerSigningKey
	md.Reset()
	a = concat(exportedSessionKey, serverSigning)
	md.Write(a)
	ServerSigningKey := md.Sum(nil)
	//ClientSealingKey
	md.Reset()
	a = concat(exportedSessionKey, clientSealing)
	md.Write(a)
	ClientSealingKey := md.Sum(nil)
	//ServerSealingKey
	md.Reset()
	a = concat(exportedSessionKey, serverSealing)
	md.Write(a)
	ServerSealingKey := md.Sum(nil)

	glog.Debugf("ClientSigningKey:%s", hex.EncodeToString(ClientSigningKey))
	glog.Debugf("ServerSigningKey:%s", hex.EncodeToString(ServerSigningKey))
	glog.Debugf("ClientSealingKey:%s", hex.EncodeToString(ClientSealingKey))
	glog.Debugf("ServerSealingKey:%s", hex.EncodeToString(ServerSealingKey))

	encryptRC4, _ := rc4.NewCipher(ClientSealingKey)
	decryptRC4, _ := rc4.NewCipher(ServerSealingKey)

	ntlmSec := &NTLMv2Security{encryptRC4, decryptRC4, ClientSigningKey, ServerSigningKey, 0}

	return n.authenticateMessage, ntlmSec
}

func (n *NTLMv2) GetEncodedCredentials() ([]byte, []byte, []byte) {
	if n.enableUnicode {
		return core.UnicodeEncode(n.domain), core.UnicodeEncode(n.user), core.UnicodeEncode(n.password)
	}
	return []byte(n.domain), []byte(n.user), []byte(n.password)
}

type NTLMv2Security struct {
	EncryptRC4 *rc4.Cipher
	DecryptRC4 *rc4.Cipher
	SigningKey []byte
	VerifyKey  []byte
	SeqNum     uint32
}

func (n *NTLMv2Security) GssEncrypt(s []byte) []byte {
	p := make([]byte, len(s))
	n.EncryptRC4.XORKeyStream(p, s)
	b := &bytes.Buffer{}

	//signature
	core.WriteUInt32LE(n.SeqNum, b)
	core.WriteBytes(s, b)
	s1 := HMAC_MD5(n.SigningKey, b.Bytes())[:8]
	checksum := make([]byte, 8)
	n.EncryptRC4.XORKeyStream(checksum, s1)
	b.Reset()
	core.WriteUInt32LE(0x00000001, b)
	core.WriteBytes(checksum, b)
	core.WriteUInt32LE(n.SeqNum, b)

	core.WriteBytes(p, b)

	n.SeqNum++

	return b.Bytes()
}
func (n *NTLMv2Security) GssDecrypt(s []byte) []byte {
	r := bytes.NewReader(s)
	core.ReadUInt32LE(r) //version
	checksum, _ := core.ReadBytes(8, r)
	seqNum, _ := core.ReadUInt32LE(r)
	data, _ := core.ReadBytes(r.Len(), r)

	p := make([]byte, len(data))
	n.DecryptRC4.XORKeyStream(p, data)

	check := make([]byte, len(checksum))
	n.DecryptRC4.XORKeyStream(check, checksum)

	b := &bytes.Buffer{}
	core.WriteUInt32LE(seqNum, b)
	core.WriteBytes(p, b)
	verify := HMAC_MD5(n.VerifyKey, b.Bytes())
	if string(verify) != string(check) {
		return nil
	}
	return p
}
