package glog

import (
	"fmt"
	"log"
	"sync"
)

// logger and level are process-wide globals. They are written from any
// goroutine that calls SetLogger/SetLevel (brutespray calls both at the top
// of every RDP attempt) and read from every grdp reader goroutine on every
// protocol frame. All access is serialized by mu; the unsynchronized
// version was a data race reported by Go's race detector whenever an RDP
// attempt overlapped another attempt's dying reader goroutine.
var (
	mu     sync.Mutex
	logger *log.Logger
	level  = TRACE
)

type LEVEL int

const (
	TRACE LEVEL = iota
	DEBUG
	INFO
	WARN
	ERROR
	NONE
)

func SetLogger(l *log.Logger) {
	l.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	mu.Lock()
	defer mu.Unlock()
	logger = l
}

func SetLevel(l LEVEL) {
	mu.Lock()
	defer mu.Unlock()
	level = l
}

// checkLocked panics when logging is attempted before a logger was set.
// Callers must hold mu.
func checkLocked() {
	if logger == nil && level != NONE {
		panic("logger not inited")
	}
}

func Trace(v ...interface{}) {
	mu.Lock()
	defer mu.Unlock()
	checkLocked()
	if level <= TRACE {
		logger.SetPrefix("[TRACE]")
		logger.Output(2, fmt.Sprintln(v...))
	}
}
func Tracef(f string, v ...interface{}) {
	mu.Lock()
	defer mu.Unlock()
	checkLocked()
	if level <= TRACE {
		logger.SetPrefix("[TRACE]")
		logger.Output(2, fmt.Sprintln(fmt.Sprintf(f, v...)))
	}
}
func Debug(v ...interface{}) {
	mu.Lock()
	defer mu.Unlock()
	checkLocked()
	if level <= DEBUG {
		logger.SetPrefix("[DEBUG]")
		logger.Output(2, fmt.Sprintln(v...))
	}
}
func Debugf(f string, v ...interface{}) {
	mu.Lock()
	defer mu.Unlock()
	checkLocked()
	if level <= DEBUG {
		logger.SetPrefix("[DEBUG]")
		logger.Output(2, fmt.Sprintln(fmt.Sprintf(f, v...)))
	}
}
func Info(v ...interface{}) {
	mu.Lock()
	defer mu.Unlock()
	checkLocked()
	if level <= INFO {
		logger.SetPrefix("[INFO]")
		logger.Output(2, fmt.Sprintln(v...))
	}
}
func Infof(f string, v ...interface{}) {
	mu.Lock()
	defer mu.Unlock()
	checkLocked()
	if level <= INFO {
		logger.SetPrefix("[INFO]")
		logger.Output(2, fmt.Sprintln(fmt.Sprintf(f, v...)))
	}
}
func Warn(v ...interface{}) {
	mu.Lock()
	defer mu.Unlock()
	checkLocked()
	if level <= WARN {
		logger.SetPrefix("[WARN]")
		logger.Output(2, fmt.Sprintln(v...))
	}
}
func Warnf(f string, v ...interface{}) {
	mu.Lock()
	defer mu.Unlock()
	checkLocked()
	if level <= WARN {
		logger.SetPrefix("[WARN]")
		logger.Output(2, fmt.Sprintln(fmt.Sprintf(f, v...)))
	}
}
func Error(v ...interface{}) {
	mu.Lock()
	defer mu.Unlock()
	checkLocked()
	if level <= ERROR {
		logger.SetPrefix("[ERROR]")
		logger.Output(2, fmt.Sprintln(v...))
	}
}
func Errorf(f string, v ...interface{}) {
	mu.Lock()
	defer mu.Unlock()
	checkLocked()
	if level <= ERROR {
		logger.SetPrefix("[ERROR]")
		logger.Output(2, fmt.Sprintln(fmt.Sprintf(f, v...)))
	}
}
