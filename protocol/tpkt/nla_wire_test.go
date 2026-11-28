package tpkt_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/x90skysn3k/grdp/client"
	"github.com/x90skysn3k/grdp/core"
	"github.com/x90skysn3k/grdp/glog"
	"github.com/x90skysn3k/grdp/protocol/nla"
)

// Exercise the real public login path: TCP -> X224 -> TLS -> CredSSP -> NTLM.
// A panic in the asynchronous X224 reader fails the process, not just this call.
func TestLoginAuthOnlyCredSSPFailures(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	config := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	marshal := func(req nla.TSRequest) []byte {
		t.Helper()
		b, err := asn1.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	malformed := wireChallenge(true)
	binary.LittleEndian.PutUint32(malformed[16:20], 48) // issue #378: unsigned 48-56
	malformed = malformed[:60]
	cases := []struct {
		name                string
		challenge, response []byte
		kind                core.RDPErrorKind
		timeout             bool
		invalidTLS          bool
	}{
		{name: "reported target offset underflow", challenge: marshal(nla.TSRequest{Version: 2, NegoTokens: []nla.NegoToken{{Data: malformed}}}), kind: core.ErrKindProtocol},
		{name: "empty NTLM token", challenge: marshal(nla.TSRequest{Version: 2, NegoTokens: []nla.NegoToken{{}}}), kind: core.ErrKindProtocol},
		{name: "missing NTLM token", challenge: marshal(nla.TSRequest{Version: 2}), kind: core.ErrKindProtocol},
		{name: "initial credential rejection", challenge: marshal(nla.TSRequest{Version: 2, ErrorCode: 0xc000006d}), kind: core.ErrKindAuth},
		{name: "unsupported server status", challenge: marshal(nla.TSRequest{Version: 2, ErrorCode: 0xc00000bb}), kind: core.ErrKindProtocol},
		{name: "invalid negative status", challenge: marshal(nla.TSRequest{Version: 2, ErrorCode: -1}), kind: core.ErrKindProtocol},
		{name: "invalid DER length", challenge: []byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff}, kind: core.ErrKindProtocol},
		{name: "invalid DER tag", challenge: []byte{0x31, 0}, kind: core.ErrKindProtocol},
		{name: "truncated DER transport", challenge: []byte{0x30, 0x82, 1}, kind: core.ErrKindNetwork},
		{name: "challenge timeout", kind: core.ErrKindTimeout, timeout: true},
		{name: "TLS failure", kind: core.ErrKindTLS, invalidTLS: true},
	}
	for _, version := range []bool{false, true} {
		name := "unversioned"
		if version {
			name = "versioned"
		}
		challenge := marshal(nla.TSRequest{Version: 2, NegoTokens: []nla.NegoToken{{Data: wireChallenge(version)}}})
		for _, status := range []int64{0xc000006d, 0xc000006a, 0xc0000234} {
			cases = append(cases, struct {
				name                string
				challenge, response []byte
				kind                core.RDPErrorKind
				timeout             bool
				invalidTLS          bool
			}{name: fmt.Sprintf("%s credential rejection %x", name, status), challenge: challenge, response: marshal(nla.TSRequest{Version: 2, ErrorCode: status}), kind: core.ErrKindAuth})
		}
		cases = append(cases, struct {
			name                string
			challenge, response []byte
			kind                core.RDPErrorKind
			timeout             bool
			invalidTLS          bool
		}{name: name + " empty pubkey response", challenge: challenge, response: marshal(nla.TSRequest{Version: 2}), kind: core.ErrKindProtocol})
		cases = append(cases, struct {
			name                string
			challenge, response []byte
			kind                core.RDPErrorKind
			timeout             bool
			invalidTLS          bool
		}{name: name + " truncated pubkey response", challenge: challenge, response: marshal(nla.TSRequest{Version: 2, PubKeyAuth: []byte{1}}), kind: core.ErrKindProtocol})
		cases = append(cases, struct {
			name                string
			challenge, response []byte
			kind                core.RDPErrorKind
			timeout             bool
			invalidTLS          bool
		}{name: name + " pubkey timeout", challenge: challenge, kind: core.ErrKindTimeout, timeout: true})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			serverDone := make(chan error, 1)
			go func() {
				serverDone <- func() error {
					conn, err := listener.Accept()
					if err != nil {
						return err
					}
					defer conn.Close()
					if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
						return err
					}
					header := make([]byte, 4)
					if _, err := io.ReadFull(conn, header); err != nil {
						return err
					}
					size := int(binary.BigEndian.Uint16(header[2:4]))
					if size < 4 {
						return fmt.Errorf("short X224 request")
					}
					if _, err := io.CopyN(io.Discard, conn, int64(size-4)); err != nil {
						return err
					}
					// X224 connection confirm, selecting PROTOCOL_HYBRID.
					if _, err := conn.Write([]byte{3, 0, 0, 19, 14, 0xd0, 0, 0, 0, 0, 0, 2, 0, 8, 0, 2, 0, 0, 0}); err != nil {
						return err
					}
					if tc.invalidTLS {
						_, err := conn.Write([]byte("not a TLS record"))
						return err
					}
					secure := tls.Server(conn, config)
					if err := secure.Handshake(); err != nil {
						return err
					}
					if _, err := readWireDER(secure); err != nil {
						return err
					}
					if len(tc.challenge) != 0 {
						if _, err := secure.Write(tc.challenge); err != nil {
							return err
						}
					}
					if tc.name == "truncated DER transport" {
						return nil
					}
					if len(tc.response) != 0 || (tc.timeout && len(tc.challenge) != 0) {
						wire, err := readWireDER(secure)
						if err != nil {
							return err
						}
						req, err := nla.DecodeDERTRequest(wire)
						if err != nil {
							return err
						}
						if len(req.NegoTokens) != 1 || len(req.PubKeyAuth) < 17 {
							return fmt.Errorf("missing NTLM authentication or public-key binding")
						}
						token := req.NegoTokens[0].Data
						if len(token) < 88 || string(token[:8]) != "NTLMSSP\x00" || binary.LittleEndian.Uint32(token[8:12]) != 3 {
							return fmt.Errorf("invalid authenticate wire message")
						}
						if len(tc.response) != 0 {
							if _, err := secure.Write(tc.response); err != nil {
								return err
							}
						}
					}
					// Failure must not send delegated credentials. The caller closes
					// after the bounded LoginAuthOnly return, so no read may hang.
					one := make([]byte, 1)
					if n, err := secure.Read(one); n != 0 || err != io.EOF {
						return fmt.Errorf("expected client close without credential delegation: n=%d err=%v", n, err)
					}
					return nil
				}()
			}()
			setting := client.NewSetting()
			setting.LogLevel = glog.NONE
			c := client.NewClient(listener.Addr().String(), "Domain\\User", "Password", client.TC_RDP, setting)
			defer c.Close()
			budget := 2 * time.Second
			if tc.timeout {
				budget = 250 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			start := time.Now()
			err = c.LoginAuthOnly(ctx)
			c.Close()
			var rdpErr *core.RDPError
			if !errors.As(err, &rdpErr) || rdpErr.Kind != tc.kind {
				t.Fatalf("LoginAuthOnly error = %v, want kind %v", err, tc.kind)
			}
			if time.Since(start) > budget+time.Second {
				t.Fatal("login exceeded bounded context")
			}
			select {
			case err := <-serverDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(6 * time.Second):
				t.Fatal("fixture did not observe bounded client shutdown")
			}
		})
	}
}

func wireChallenge(version bool) []byte {
	header := 48
	flags := uint32(nla.NTLMSSP_NEGOTIATE_UNICODE | nla.NTLMSSP_NEGOTIATE_NTLM | nla.NTLMSSP_NEGOTIATE_TARGET_INFO | nla.NTLMSSP_NEGOTIATE_KEY_EXCH | nla.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY)
	if version {
		header = 56
		flags |= nla.NTLMSSP_NEGOTIATE_VERSION
	}
	// A timestamp exercises the optional MIC path over the exact challenge.
	info := []byte{7, 0, 8, 0, 0, 0x90, 0xd3, 0x36, 0xb7, 0x34, 0xc3, 1, 0, 0, 0, 0}
	wire := make([]byte, header+12+len(info))
	copy(wire, "NTLMSSP\x00")
	binary.LittleEndian.PutUint32(wire[8:12], 2)
	binary.LittleEndian.PutUint16(wire[12:14], 12)
	binary.LittleEndian.PutUint16(wire[14:16], 12)
	binary.LittleEndian.PutUint32(wire[16:20], uint32(header))
	binary.LittleEndian.PutUint32(wire[20:24], flags)
	copy(wire[24:32], []byte{1, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef})
	binary.LittleEndian.PutUint16(wire[40:42], uint16(len(info)))
	binary.LittleEndian.PutUint16(wire[42:44], uint16(len(info)))
	binary.LittleEndian.PutUint32(wire[44:48], uint32(header+12))
	if version {
		copy(wire[48:56], []byte{6, 1, 0xb1, 0x1d, 0, 0, 0, 15})
	}
	copy(wire[header:], []byte{'D', 0, 'o', 0, 'm', 0, 'a', 0, 'i', 0, 'n', 0})
	copy(wire[header+12:], info)
	return wire
}

func readWireDER(r io.Reader) ([]byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	length := int(header[1])
	if length >= 128 {
		count := length & 127
		if count == 0 || count > 4 {
			return nil, fmt.Errorf("invalid DER length")
		}
		encoded := make([]byte, count)
		if _, err := io.ReadFull(r, encoded); err != nil {
			return nil, err
		}
		header = append(header, encoded...)
		length = 0
		for _, b := range encoded {
			length = length<<8 | int(b)
		}
	}
	if length > 65536 {
		return nil, fmt.Errorf("oversized DER frame")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return bytes.Join([][]byte{header, payload}, nil), nil
}
