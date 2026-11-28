package nla

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/x90skysn3k/grdp/glog"
)

// Build the server's wire message independently of ChallengeMessage.Serialize.
func challengeFixture(version bool, targetInfo []byte) []byte {
	header := 48
	flags := uint32(NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_TARGET_INFO | NTLMSSP_NEGOTIATE_KEY_EXCH | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)
	if version {
		header = 56
		flags |= NTLMSSP_NEGOTIATE_VERSION
	}
	name := []byte{'D', 0, 'o', 0, 'm', 0, 'a', 0, 'i', 0, 'n', 0}
	wire := make([]byte, header+len(name)+len(targetInfo))
	copy(wire, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(wire[8:12], 2)
	binary.LittleEndian.PutUint16(wire[12:14], uint16(len(name)))
	binary.LittleEndian.PutUint16(wire[14:16], uint16(len(name)))
	binary.LittleEndian.PutUint32(wire[16:20], uint32(header))
	binary.LittleEndian.PutUint32(wire[20:24], flags)
	copy(wire[24:32], []byte{1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef})
	binary.LittleEndian.PutUint16(wire[40:42], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint16(wire[42:44], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint32(wire[44:48], uint32(header+len(name)))
	if version {
		copy(wire[48:56], []byte{6, 1, 0xb1, 0x1d, 0, 0, 0, 15})
	}
	copy(wire[header:], name)
	copy(wire[header+len(name):], targetInfo)
	return wire
}

func TestGetAuthenticateMessageRejectsMalformedChallenge(t *testing.T) {
	glog.SetLevel(glog.NONE)
	eol := []byte{0, 0, 0, 0}
	cases := []struct {
		name string
		wire []byte
	}{
		{"empty", nil},
		{"short fixed header", make([]byte, 47)},
		{"truncated AV header", challengeFixture(false, []byte{7, 0, 8})},
		{"truncated AV value", challengeFixture(false, []byte{1, 0, 4, 0, 'a', 0})},
		{"short timestamp", challengeFixture(false, []byte{7, 0, 4, 0, 1, 2, 3, 4, 0, 0, 0, 0})},
		{"oversized timestamp", challengeFixture(true, []byte{7, 0, 0xff, 0xff, 0, 0, 0, 0})},
		{"zero-length timestamp", challengeFixture(false, []byte{7, 0, 0, 0, 0, 0, 0, 0})},
		{"timestamp without EOL", challengeFixture(true, []byte{7, 0, 8, 0, 1, 2, 3, 4, 5, 6, 7, 8})},
		{"truncated AV after timestamp", challengeFixture(false, []byte{7, 0, 8, 0, 1, 2, 3, 4, 5, 6, 7, 8, 1})},
		{"missing EOL", challengeFixture(false, []byte{1, 0, 2, 0, 'a', 0})},
		{"nonempty EOL", challengeFixture(true, []byte{0, 0, 1, 0, 0})},
		{"data after EOL", challengeFixture(false, []byte{0, 0, 0, 0, 1})},
		{"odd Unicode AV", challengeFixture(false, []byte{1, 0, 1, 0, 'a', 0, 0, 0, 0})},
		{"invalid flags AV", challengeFixture(false, []byte{6, 0, 0, 0, 0, 0, 0, 0})},
	}
	mutate := func(name string, version bool, edit func([]byte) []byte) {
		cases = append(cases, struct {
			name string
			wire []byte
		}{name, edit(challengeFixture(version, eol))})
	}
	mutate("invalid signature", false, func(b []byte) []byte { b[0] = 'X'; return b })
	mutate("invalid message type", true, func(b []byte) []byte { b[8] = 1; return b })
	mutate("missing version", true, func(b []byte) []byte { return b[:48] })
	mutate("truncated version", true, func(b []byte) []byte { return b[:55] })
	mutate("odd Unicode target name", false, func(b []byte) []byte {
		binary.LittleEndian.PutUint16(b[12:14], 3)
		return b
	})
	mutate("reported issue version target offset 48", true, func(b []byte) []byte {
		binary.LittleEndian.PutUint32(b[16:20], 48)
		return b[:60]
	})
	for _, version := range []bool{false, true} {
		label := "unversioned "
		if version {
			label = "versioned "
		}
		for _, field := range []struct {
			name           string
			length, offset int
		}{{"target name", 12, 16}, {"target info", 40, 44}} {
			mutate(label+field.name+" header offset", version, func(b []byte) []byte {
				binary.LittleEndian.PutUint32(b[field.offset:field.offset+4], 4)
				return b
			})
			mutate(label+field.name+" wrapping offset", version, func(b []byte) []byte {
				binary.LittleEndian.PutUint32(b[field.offset:field.offset+4], 0xfffffffc)
				return b
			})
			mutate(label+field.name+" end overrun", version, func(b []byte) []byte {
				binary.LittleEndian.PutUint16(b[field.length:field.length+2], 0xffff)
				return b
			})
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ntlm := NewNTLMv2("Domain", "User", "Password")
			ntlm.GetNegotiateMessage()
			msg, security := ntlm.GetAuthenticateMessage(tc.wire)
			if msg != nil || security != nil {
				t.Fatal("malformed challenge produced an authenticate message or security context")
			}
		})
	}
}

func TestGetAuthenticateMessageValidOptionalVersion(t *testing.T) {
	glog.SetLevel(glog.NONE)
	for _, version := range []bool{false, true} {
		for _, timestamp := range []bool{false, true} {
			name := "unversioned"
			if version {
				name = "versioned"
			}
			if timestamp {
				name += " timestamp MIC"
			}
			t.Run(name, func(t *testing.T) {
				info := []byte{0, 0, 0, 0}
				if timestamp {
					info = []byte{7, 0, 8, 0, 0, 0x90, 0xd3, 0x36, 0xb7, 0x34, 0xc3, 1, 0, 0, 0, 0}
				}
				challenge := challengeFixture(version, info)
				ntlm := NewNTLMv2("Domain", "User", "Password")
				negotiate := ntlm.GetNegotiateMessage().Serialize()
				msg, security := ntlm.GetAuthenticateMessage(challenge)
				if msg == nil || security == nil {
					t.Fatal("valid challenge rejected")
				}
				wire := msg.Serialize()
				if string(wire[:8]) != "NTLMSSP\x00" || binary.LittleEndian.Uint32(wire[8:12]) != 3 {
					t.Fatal("invalid authenticate signature/type")
				}
				field := func(at int) []byte {
					t.Helper()
					length := int(binary.LittleEndian.Uint16(wire[at : at+2]))
					offset := int(binary.LittleEndian.Uint32(wire[at+4 : at+8]))
					if offset < 88 || offset > len(wire) || length > len(wire)-offset {
						t.Fatal("authenticate field out of bounds")
					}
					return wire[offset : offset+length]
				}
				if !bytes.Equal(field(28), []byte{'D', 0, 'o', 0, 'm', 0, 'a', 0, 'i', 0, 'n', 0}) || !bytes.Equal(field(36), []byte{'U', 0, 's', 0, 'e', 0, 'r', 0}) {
					t.Fatal("wrong Unicode domain/user fields")
				}
				if binary.LittleEndian.Uint32(wire[60:64]) != binary.LittleEndian.Uint32(challenge[20:24]) {
					t.Fatal("negotiated flags changed")
				}
				nt, lm := field(20), field(12)
				// With a server timestamp the client computes a MIC, which
				// (per MS-NLMP 3.1.5.1.2) inserts MsvAvFlags (MIC_PROVIDED)
				// and MsvAvTargetName (TERMSRV/<server>) before MsvAvEOL.
				expectedInfo := info
				if timestamp {
					spn := []byte("TERMSRV/Domain")
					spnU := make([]byte, 2*len(spn))
					for i, c := range spn {
						spnU[2*i] = c
					}
					expectedInfo = append([]byte(nil), info[:len(info)-4]...)
					expectedInfo = binary.LittleEndian.AppendUint16(expectedInfo, 6)  // MsvAvFlags
					expectedInfo = binary.LittleEndian.AppendUint16(expectedInfo, 4)
					expectedInfo = binary.LittleEndian.AppendUint32(expectedInfo, 2)   // MIC_PROVIDED
					expectedInfo = binary.LittleEndian.AppendUint16(expectedInfo, 9)   // MsvAvTargetName
					expectedInfo = binary.LittleEndian.AppendUint16(expectedInfo, uint16(len(spnU)))
					expectedInfo = append(expectedInfo, spnU...)
					expectedInfo = append(expectedInfo, 0, 0, 0, 0)                    // MsvAvEOL
				}
				if len(nt) != 48+len(expectedInfo) || len(lm) != 24 || !bytes.Equal(nt[16:24], []byte{1, 1, 0, 0, 0, 0, 0, 0}) || !bytes.Equal(nt[44:len(nt)-4], expectedInfo) {
					t.Fatal("wrong NTLMv2 response layout/target info")
				}
				if !bytes.Equal(lm[16:24], nt[32:40]) {
					t.Fatal("client challenge differs between NT and LM responses")
				}
				if timestamp && !bytes.Equal(nt[24:32], info[4:12]) {
					t.Fatal("server timestamp not preserved")
				}
				// ResponseKeyNT from the MS-NLMP User/Domain/Password worked example.
				key, _ := hex.DecodeString("0c868a403bfd7a93a3001ef22ef02e3f")
				mac := hmac.New(md5.New, key)
				mac.Write([]byte{1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef})
				mac.Write(nt[16:])
				if !hmac.Equal(nt[:16], mac.Sum(nil)) {
					t.Fatal("NT proof does not authenticate the server challenge and response blob")
				}
				if timestamp {
					mac.Reset()
					mac.Write(nt[:16])
					rc, err := rc4.NewCipher(mac.Sum(nil))
					if err != nil {
						t.Fatal(err)
					}
					sessionKey := make([]byte, 16)
					if len(field(52)) != len(sessionKey) {
						t.Fatal("wrong encrypted session key length")
					}
					rc.XORKeyStream(sessionKey, field(52))
					mic := append([]byte(nil), wire[72:88]...)
					clear(wire[72:88])
					mac = hmac.New(md5.New, sessionKey)
					mac.Write(negotiate)
					mac.Write(challenge)
					mac.Write(wire)
					if !hmac.Equal(mic, mac.Sum(nil)) {
						t.Fatal("MIC does not cover the original optional-version challenge")
					}
				} else if !bytes.Equal(wire[72:88], make([]byte, 16)) {
					t.Fatal("unexpected MIC without server timestamp")
				}
			})
		}
	}
}

func TestGetAuthenticateMessageAllowsEmptySecurityBuffers(t *testing.T) {
	glog.SetLevel(glog.NONE)
	for _, version := range []bool{false, true} {
		wire := challengeFixture(version, nil)
		binary.LittleEndian.PutUint16(wire[12:14], 0)
		binary.LittleEndian.PutUint32(wire[16:20], 0xffffffff)
		binary.LittleEndian.PutUint32(wire[44:48], 0xffffffff)
		ntlm := NewNTLMv2("Domain", "User", "Password")
		ntlm.GetNegotiateMessage()
		msg, sec := ntlm.GetAuthenticateMessage(wire)
		if msg == nil || sec == nil || msg.NtChallengeResponseLen != 48 {
			t.Fatal("zero-length buffers must ignore their unused offsets")
		}
	}
}
