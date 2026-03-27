package tpkt

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/x90skysn3k/grdp/protocol/nla"
)

func TestComputeHash(t *testing.T) {
	magic := "CredSSP Client-To-Server Binding Hash\x00"
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	pubkey := []byte("test-public-key-data")

	got := computeHash(magic, nonce, pubkey)

	// Verify against manual SHA-256 computation
	h := sha256.New()
	h.Write([]byte(magic))
	h.Write(nonce)
	h.Write(pubkey)
	want := h.Sum(nil)

	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Errorf("computeHash mismatch:\n  got  %s\n  want %s",
			hex.EncodeToString(got), hex.EncodeToString(want))
	}

	if len(got) != 32 {
		t.Errorf("hash length: got %d, want 32", len(got))
	}
}

func TestComputeHash_DifferentMagicProducesDifferentHash(t *testing.T) {
	nonce := make([]byte, 32)
	pubkey := []byte("key")

	clientHash := computeHash("CredSSP Client-To-Server Binding Hash\x00", nonce, pubkey)
	serverHash := computeHash("CredSSP Server-To-Client Binding Hash\x00", nonce, pubkey)

	if hex.EncodeToString(clientHash) == hex.EncodeToString(serverHash) {
		t.Error("client and server hashes should differ")
	}
}

func TestCheckErrorCode_Zero(t *testing.T) {
	tsreq := &nla.TSRequest{Version: 6, ErrorCode: 0}
	if err := checkErrorCode(tsreq); err != nil {
		t.Errorf("expected nil, got: %v", err)
	}
}

func TestCheckErrorCode_KnownCodes(t *testing.T) {
	tests := []struct {
		code     int
		contains string
	}{
		{-1073741790, "STATUS_ACCESS_DENIED"},       // 0xC0000022 as signed
		{-1073741715, "STATUS_LOGON_FAILURE"},       // 0xC000006D as signed
		{-1073741714, "STATUS_ACCOUNT_RESTRICTION"}, // 0xC000006E as signed
		{-2146892986, "SEC_E_DELEGATION_POLICY"},    // 0x80090346 as signed
	}

	for _, tt := range tests {
		tsreq := &nla.TSRequest{Version: 6, ErrorCode: tt.code}
		err := checkErrorCode(tsreq)
		if err == nil {
			t.Errorf("code 0x%X: expected error, got nil", tt.code)
			continue
		}
		if !strings.Contains(err.Error(), tt.contains) {
			t.Errorf("code 0x%X: error %q should contain %q", tt.code, err.Error(), tt.contains)
		}
		if !strings.Contains(err.Error(), "NTSTATUS") {
			t.Errorf("code 0x%X: error %q should contain NTSTATUS", tt.code, err.Error())
		}
	}
}

func TestCheckErrorCode_UnknownCode(t *testing.T) {
	tsreq := &nla.TSRequest{Version: 6, ErrorCode: 0x12345}
	err := checkErrorCode(tsreq)
	if err == nil {
		t.Fatal("expected error for non-zero code")
	}
	if !strings.Contains(err.Error(), "0x00012345") {
		t.Errorf("error %q should contain hex code", err.Error())
	}
}
