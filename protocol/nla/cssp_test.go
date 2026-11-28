package nla

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestEncodeDERTRequest(t *testing.T) {
	ntlm := NewNTLMv2("", "", "")
	msg := ntlm.GetNegotiateMessage()
	result := EncodeDERTRequest(6, []Message{msg}, nil, nil, nil)
	if len(result) == 0 {
		t.Error("expected non-empty encoded request")
	}
}

func TestDecodeDERTRequestCredentialError(t *testing.T) {
	// Positive ASN.1 INTEGER 0xc000006d (STATUS_LOGON_FAILURE), not int32.
	wire, _ := hex.DecodeString("300ea003020102a407020500c000006d")
	req, err := DecodeDERTRequest(wire)
	if err != nil {
		t.Fatal(err)
	}
	if req.Version != 2 || req.ErrorCode != 0xc000006d {
		t.Fatalf("wrong CredSSP version/status: %+v", req)
	}
}

func TestDecodeDERTRequestRejectsInvalidStatusAndTrailingData(t *testing.T) {
	for _, wireHex := range []string{
		"300aa003020102a4030201ff",         // negative NTSTATUS
		"300ea003020102a40702050100000000", // more than uint32
		"3005a00302010200",                 // trailing bytes outside the sequence
	} {
		wire, err := hex.DecodeString(wireHex)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeDERTRequest(wire); err == nil {
			t.Fatalf("invalid CredSSP request accepted: %x", wire)
		}
	}
}

func TestTSRequestRoundTrip_V6WithAllFields(t *testing.T) {
	nonce := []byte("0123456789abcdef0123456789abcdef")
	pubKeyAuth := []byte("encrypted-hash-data")

	ntlm := NewNTLMv2("DOM", "user", "pass")
	msg := ntlm.GetNegotiateMessage()

	encoded := EncodeDERTRequest(6, []Message{msg}, nil, pubKeyAuth, nonce)
	decoded, err := DecodeDERTRequest(encoded)
	if err != nil {
		t.Fatal("decode failed:", err)
	}

	if decoded.Version != 6 {
		t.Errorf("version: got %d, want 6", decoded.Version)
	}
	if len(decoded.NegoTokens) != 1 {
		t.Fatalf("NegoTokens count: got %d, want 1", len(decoded.NegoTokens))
	}
	if !bytes.Equal(decoded.PubKeyAuth, pubKeyAuth) {
		t.Error("PubKeyAuth mismatch")
	}
	if !bytes.Equal(decoded.ClientNonce, nonce) {
		t.Error("ClientNonce mismatch")
	}
	if decoded.ErrorCode != 0 {
		t.Errorf("ErrorCode: got %d, want 0", decoded.ErrorCode)
	}
}

func TestTSRequestRoundTrip_V2Minimal(t *testing.T) {
	ntlm := NewNTLMv2("", "user", "pass")
	msg := ntlm.GetNegotiateMessage()

	encoded := EncodeDERTRequest(2, []Message{msg}, nil, nil, nil)
	decoded, err := DecodeDERTRequest(encoded)
	if err != nil {
		t.Fatal("decode failed:", err)
	}

	if decoded.Version != 2 {
		t.Errorf("version: got %d, want 2", decoded.Version)
	}
	if len(decoded.NegoTokens) != 1 {
		t.Fatalf("NegoTokens count: got %d, want 1", len(decoded.NegoTokens))
	}
	if len(decoded.PubKeyAuth) != 0 {
		t.Error("expected empty PubKeyAuth")
	}
	if len(decoded.ClientNonce) != 0 {
		t.Error("expected empty ClientNonce")
	}
}

func TestTSRequestRoundTrip_AuthInfoOnly(t *testing.T) {
	authInfo := []byte("encrypted-credentials")

	encoded := EncodeDERTRequest(6, nil, authInfo, nil, nil)
	decoded, err := DecodeDERTRequest(encoded)
	if err != nil {
		t.Fatal("decode failed:", err)
	}

	if decoded.Version != 6 {
		t.Errorf("version: got %d, want 6", decoded.Version)
	}
	if len(decoded.NegoTokens) != 0 {
		t.Errorf("NegoTokens count: got %d, want 0", len(decoded.NegoTokens))
	}
	if !bytes.Equal(decoded.AuthInfo, authInfo) {
		t.Error("AuthInfo mismatch")
	}
}

func TestTSCredentialsRoundTrip(t *testing.T) {
	domain := []byte("DOMAIN")
	user := []byte("admin")
	pass := []byte("secret")

	encoded := EncodeDERTCredentials(domain, user, pass)
	decoded, err := DecodeDERTCredentials(encoded)
	if err != nil {
		t.Fatal("decode failed:", err)
	}

	if decoded.CredType != 1 {
		t.Errorf("CredType: got %d, want 1", decoded.CredType)
	}
	if len(decoded.Credentials) == 0 {
		t.Error("expected non-empty Credentials")
	}
}
