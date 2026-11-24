package glog

import (
	"io"
	"log"
	"sync"
	"testing"
	"time"
)

// TestConcurrentSetLevelAndLogging pins the global-state contract: brutespray
// calls SetLevel+SetLogger at the top of EVERY RDP attempt, while reader
// goroutines from previous, still-dying attempts keep calling Trace/Debug on
// every protocol frame. Without the mutex these globals race, and Go's race
// detector fails the host project's -race test suite (observed in CI on
// x90skysn3k/brutespray PR #376, WARNING: DATA RACE glog.SetLevel vs
// glog.Trace).
func TestConcurrentSetLevelAndLogging(t *testing.T) {
	devNull := log.New(io.Discard, "", 0)
	SetLogger(devNull)
	SetLevel(NONE)
	defer SetLevel(TRACE)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writers: hammer SetLevel/SetLogger like concurrent RDP attempts do.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				SetLogger(devNull)
				SetLevel(NONE)
			}
		}()
	}

	// Readers: log on every "frame" like the tpkt read chain.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				Trace("frame")
				Debug("frame")
				Info("frame")
				Warn("frame")
				Error("frame")
			}
		}()
	}

	// Let them collide, then stop everything cleanly.
	done := make(chan struct{})
	go func() {
		time.Sleep(200 * time.Millisecond)
		close(stop)
		close(done)
	}()
	<-done
	wg.Wait()
}
