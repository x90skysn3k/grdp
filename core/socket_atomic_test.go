package core_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/x90skysn3k/grdp/core"
)

// A timed-out login can return while its emitter goroutine is still starting
// TLS. Closing the socket must safely interrupt either phase of that handoff.
func TestSocketCloseConcurrentWithTLSStart(t *testing.T) {
	for i := 0; i < 32; i++ {
		client, peer := net.Pipe()
		socket := core.NewSocketLayer(client)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		socket.SetContext(ctx)
		start := make(chan struct{})
		handshakeDone := make(chan error, 1)
		closeDone := make(chan struct{})
		peerDone := make(chan struct{})
		go func() {
			defer close(peerDone)
			defer peer.Close()
			// Consume ClientHello, but never answer the TLS handshake.
			_, _ = io.Copy(io.Discard, peer)
		}()
		go func() {
			<-start
			handshakeDone <- socket.StartTLS()
		}()
		go func() {
			<-start
			_ = socket.Close()
			close(closeDone)
		}()
		close(start)
		select {
		case err := <-handshakeDone:
			if err == nil {
				t.Fatal("TLS handshake succeeded without a server")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Close did not interrupt TLS startup")
		}
		select {
		case <-closeDone:
		case <-time.After(2 * time.Second):
			t.Fatal("Close blocked behind the TLS handshake")
		}
		select {
		case <-peerDone:
		case <-time.After(2 * time.Second):
			t.Fatal("peer did not observe socket closure")
		}
		cancel()
	}
}
