package nla

import (
	"bytes"
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
