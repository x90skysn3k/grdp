package nla

import (
	"encoding/hex"
	"testing"
)

func TestEncodeDERTRequest(t *testing.T) {
	ntlm := NewNTLMv2("", "", "")
	msg := ntlm.GetNegotiateMessage()
	result := EncodeDERTRequest([]Message{msg}, nil, nil)
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
