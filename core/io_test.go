package core

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"testing"
	"time"
)

func TestWriteUInt16LE(t *testing.T) {
	buff := &bytes.Buffer{}
	_, _ = WriteUInt32LE(66538, buff)
	result := hex.EncodeToString(buff.Bytes())
	expected := "ea030100"
	if result != expected {
		t.Error(result, "not equals to", expected)
	}
}

// TestStartReadBytesNegativeLen pins the delivered error for a negative
// read length (was: makeslice panic in the spawned reader goroutine, see
// brutespray#366).
func TestStartReadBytesNegativeLen(t *testing.T) {
	done := make(chan error, 1)
	StartReadBytes(context.Background(), -1, bytes.NewReader([]byte("x")), func(_ []byte, err error) {
		done <- err
	})
	select {
	case err := <-done:
		if err != io.ErrUnexpectedEOF {
			t.Fatalf("err = %v, want io.ErrUnexpectedEOF", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("callback not invoked for negative length")
	}
}

// TestStartReadBytesNegativeLenIsAsync pins the documented contract that the
// callback is delivered from a goroutine AFTER StartReadBytes returned —
// callers may hold locks across the call. The callback blocks until the
// host goroutine reports StartReadBytes has returned. Synchronous delivery
// deadlocks in the callback, so the host never closes `returned` and this
// test fails deterministically on timeout; correct async delivery completes
// immediately.
func TestStartReadBytesNegativeLenIsAsync(t *testing.T) {
	returned := make(chan struct{})
	cbDone := make(chan struct{})
	go func() {
		StartReadBytes(context.Background(), -1, bytes.NewReader([]byte("x")), func(_ []byte, _ error) {
			<-returned
			close(cbDone)
		})
		close(returned)
	}()
	select {
	case <-cbDone:
	case <-time.After(2 * time.Second):
		t.Fatal("callback did not run after StartReadBytes returned (synchronous delivery or lost callback)")
	}
}

// TestStartReadBytesNegativeLenCancelledCtx pins the cancellation rule: a
// cancelled context suppresses the callback even on the fast error path.
func TestStartReadBytesNegativeLenCancelledCtx(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := make(chan struct{})
	StartReadBytes(ctx, -1, bytes.NewReader([]byte("x")), func(_ []byte, _ error) {
		close(called)
	})
	select {
	case <-called:
		t.Fatal("callback invoked despite cancelled context")
	case <-time.After(300 * time.Millisecond):
	}
}

// TestReadBytesNegativeLen pins the synchronous guard: a malformed length
// minus header overhead behaves like a truncated read, not a panic in
// make(). Licensing/capability/GCC parsers feed untrusted values here.
func TestReadBytesNegativeLen(t *testing.T) {
	b, err := ReadBytes(-4, bytes.NewReader([]byte("payload")))
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("err = %v, want io.ErrUnexpectedEOF", err)
	}
	if b != nil {
		t.Fatalf("result = %v, want nil", b)
	}
}
