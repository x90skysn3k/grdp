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
