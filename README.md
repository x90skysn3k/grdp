# grdp - Go Remote Desktop Protocol Client

A pure Go implementation of the Microsoft RDP (Remote Desktop Protocol) client, focused on authentication and programmatic access. Actively maintained fork with context support, timeout handling, and goroutine safety.

Originally forked from [icodeface/grdp](https://github.com/icodeface/grdp).

## Features

- **NTLMv2/NLA (CredSSP) authentication** - Full Network Level Authentication support
- **SSL/TLS authentication** - Standard RDP over TLS
- **Standard RDP authentication** - Legacy RDP security
- **context.Context support** - Deadlines and cancellation propagate through the entire protocol stack
- **Goroutine-safe shutdown** - Clean emitter teardown prevents goroutine leaks
- **Timeout-aware NLA handshake** - All blocking I/O respects context deadlines

## Installation

```bash
go get github.com/x90skysn3k/grdp
```

## Usage

### Quick auth check with timeout

```go
package main

import (
    "context"
    "fmt"
    "time"

    "github.com/x90skysn3k/grdp/client"
)

func main() {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    c := &client.RdpClient{}
    err := c.Login(ctx, "192.168.1.100:3389", "admin", "password", 800, 600)
    if err != nil {
        fmt.Println("Login failed:", err)
        return
    }
    defer c.Close()

    done := make(chan bool, 1)
    c.On("success", func() { done <- true })
    c.On("ready", func() { done <- true })
    c.On("error", func(e error) { done <- false })

    select {
    case ok := <-done:
        fmt.Println("Auth success:", ok)
    case <-ctx.Done():
        fmt.Println("Timeout")
    }
}
```

### Using the high-level Client with context

```go
c := client.NewClient("192.168.1.100:3389", "user", "pass", client.TC_RDP, nil)

ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
defer cancel()

err := c.LoginContext(ctx)
```

### Domain authentication

```go
// Domain\User format is handled automatically
c.Login(ctx, "host:3389", "DOMAIN\\administrator", "password", 800, 600)
```

## What's fixed vs upstream

This fork addresses critical issues in the original grdp library that made it unsuitable for production use:

| Issue | Before | After |
|-------|--------|-------|
| **Goroutine leaks** | `StartReadBytes()` spawns goroutines that block forever on dead connections | Context-aware readers exit when cancelled |
| **NLA hangs** | `StartNLA()` blocks indefinitely on read/write with no timeout | All NLA round-trips check context before blocking I/O |
| **No cancellation** | No way to cancel an in-progress connection or auth attempt | `context.Context` flows through Socket -> TPKT -> X224 -> Client |
| **Emitter leaks** | Event listeners accumulate with no cleanup on shutdown | `Emitter.Close()` clears all listeners and prevents new dispatches |
| **Hardcoded dial timeout** | `net.DialTimeout` with 3-second hardcoded timeout | `net.Dialer.DialContext` uses caller-provided context |

## Protocol Stack

```
Client (Login with context)
  -> X224 (connection negotiation)
    -> TPKT (packet framing, NLA/CredSSP)
      -> SocketLayer (TLS, raw TCP)
        -> net.Conn
```

Each layer propagates the context downward, ensuring deadlines and cancellation reach the underlying connection.

## Credits

- [icodeface/grdp](https://github.com/icodeface/grdp) - Original implementation
- [rdpy](https://github.com/citronneur/rdpy) - Python RDP reference
- [node-rdpjs](https://github.com/citronneur/node-rdpjs) - Node.js RDP reference
- [gordp](https://github.com/Madnikulin50/gordp) - Go RDP reference
- [ncrack](https://github.com/nmap/ncrack/blob/master/modules/ncrack_rdp.cc) - RDP auth module reference

## License

See [LICENSE](LICENSE) for details.
