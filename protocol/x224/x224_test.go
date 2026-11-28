package x224_test

import (
	"io"
	"testing"

	"github.com/x90skysn3k/grdp/emission"
	"github.com/x90skysn3k/grdp/glog"
	"github.com/x90skysn3k/grdp/protocol/x224"
)

// An immediate peer response can be dispatched before Write returns. Connect
// must arm its receive handler before sending the connection request.
func TestConnectAcceptsImmediateConnectionConfirm(t *testing.T) {
	glog.SetLevel(glog.NONE)
	peer := &immediateConfirmPeer{Emitter: *emission.NewEmitter()}
	connection := x224.New(peer)
	connected := false
	connection.On("connect", func(protocol uint32) {
		connected = protocol == x224.PROTOCOL_RDP
	})
	if err := connection.Connect(); err != nil {
		t.Fatal(err)
	}
	if !connected {
		t.Fatal("connection confirm arriving during request write was lost")
	}
}

type immediateConfirmPeer struct {
	emission.Emitter
}

func (p *immediateConfirmPeer) Read([]byte) (int, error) { return 0, io.EOF }
func (p *immediateConfirmPeer) Close() error             { return nil }
func (p *immediateConfirmPeer) Write(request []byte) (int, error) {
	// Legacy RDP connection confirm needs no TLS/NLA, isolating delivery order.
	p.Emit("data", []byte{6, 0xd0, 0, 0, 0, 0, 0})
	return len(request), nil
}
