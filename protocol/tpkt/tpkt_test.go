package tpkt

import (
	"net"
	"testing"
	"time"

	"github.com/x90skysn3k/grdp/core"
	"github.com/x90skysn3k/grdp/glog"
	"github.com/x90skysn3k/grdp/protocol/nla"
)

// TestRecvFastPathWithoutListener reproduces the crash from brutespray#363:
// the auth-only login flow (LoginAuthOnly) never wires a FastPath listener,
// but tpkt.New starts the read loop immediately. A server that pushes
// FastPath output after the CredSSP handshake made recvFastPath call a nil
// interface, SIGSEGV-crashing the whole process from an unrecovered
// background goroutine.
//
// The test feeds one FastPath frame with no listener attached, then proves
// the loop survived by requiring a second frame's write to complete: if the
// reader dies, net.Pipe writes block forever (cut short by the deadline).
func TestRecvFastPathWithoutListener(t *testing.T) {
	// glog panics on any Trace/Debug call when level != NONE and no logger
	// is set; the tpkt read path logs on every frame.
	glog.SetLevel(glog.NONE)

	client, server := net.Pipe()
	defer func() { _ = server.Close() }()

	ntlm := nla.NewNTLMv2("TESTDOM", "testuser", "testpass")
	tp := New(core.NewSocketLayer(server), ntlm)
	defer tp.Close()

	// FASTPATH_ACTION_X224 is 0x03; any other first byte routes the frame
	// to recvFastPath. Length 0x05 = 2 header + 3 payload bytes.
	frame := func(payload string) []byte {
		return append([]byte{0x00, byte(len(payload) + 2)}, payload...)
	}

	writeFrame := func(payload string) error {
		if err := client.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
			return err
		}
		_, err := client.Write(frame(payload))
		return err
	}

	// Frame 1: no listener attached. Old code panics here and the process
	// dies; fixed code drops the frame and keeps reading.
	if err := writeFrame("abc"); err != nil {
		t.Fatalf("first frame write: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Frame 2: only succeeds if the read loop re-armed after the drop.
	if err := writeFrame("def"); err != nil {
		t.Fatalf("second frame write (read loop dead after nil-listener drop): %v", err)
	}
}

// TestMalformedShortFastPathLengthNoPanic reproduces the makeslice panic
// from x90skysn3k/brutespray#366 (v2.7.7 report): a hostile/garbage server
// answers the header read with first byte != X224 and a short length below
// the 3-byte fastpath minimum (e.g. 0x00 0x01). recvHeader computed
// lastShortLength-2 == -1 and StartReadBytes ran make([]byte, -1) inside
// its spawned read goroutine -> "panic: runtime error: makeslice: len out
// of range" killing the whole process (unreachable by caller recover).
func TestMalformedShortFastPathLengthNoPanic(t *testing.T) {
	glog.SetLevel(glog.NONE)

	client, server := net.Pipe()
	defer func() { _ = server.Close() }()

	ntlm := nla.NewNTLMv2("TESTDOM", "testuser", "testpass")
	tp := New(core.NewSocketLayer(server), ntlm)
	defer tp.Close()

	errCh := make(chan error, 4)
	tp.On("error", func(err error) {
		select {
		case errCh <- err:
		default:
		}
	})

	// 0x00 = FASTPATH_ACTION_FASTPATH (not X224); length 0x01 < minimum 3.
	if err := client.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte{0x00, 0x01}); err != nil {
		t.Fatalf("malformed frame write: %v", err)
	}

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected a typed error event for the malformed frame")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no error event surfaced from the malformed frame")
	}
	// Surviving to this line proves no panic killed the process.
}

// TestMalformedTPKTLengthNoPanic covers recvExtendedHeader: TPKT total
// length below the 4-byte header (size-4 used to panic inside the read
// goroutine callback).
func TestMalformedTPKTLengthNoPanic(t *testing.T) {
	glog.SetLevel(glog.NONE)

	client, server := net.Pipe()
	defer func() { _ = server.Close() }()

	ntlm := nla.NewNTLMv2("TESTDOM", "testuser", "testpass")
	tp := New(core.NewSocketLayer(server), ntlm)
	defer tp.Close()

	errCh := make(chan error, 4)
	tp.On("error", func(err error) {
		select {
		case errCh <- err:
		default:
		}
	})

	// 0x03 = X224; extended length 0x0002 < 4.
	if err := client.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte{0x03, 0x00, 0x00, 0x02}); err != nil {
		t.Fatalf("malformed frame write: %v", err)
	}

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected a typed error event for the malformed frame")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no error event surfaced from the malformed frame")
	}
}

// TestMalformedExtendedFastPathLengthNoPanic covers
// recvExtendedFastPathHeader: extended length 0x80 0x00 -> packetSize 0,
// packetSize-3 used to panic.
func TestMalformedExtendedFastPathLengthNoPanic(t *testing.T) {
	glog.SetLevel(glog.NONE)

	client, server := net.Pipe()
	defer func() { _ = server.Close() }()

	ntlm := nla.NewNTLMv2("TESTDOM", "testuser", "testpass")
	tp := New(core.NewSocketLayer(server), ntlm)
	defer tp.Close()

	errCh := make(chan error, 4)
	tp.On("error", func(err error) {
		select {
		case errCh <- err:
		default:
		}
	})

	// 0x00 action, 0x80 extended-length flag, next byte 0x00 -> size 0 < 3.
	if err := client.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte{0x00, 0x80, 0x00}); err != nil {
		t.Fatalf("malformed frame write: %v", err)
	}

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected a typed error event for the malformed frame")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no error event surfaced from the malformed frame")
	}
}
