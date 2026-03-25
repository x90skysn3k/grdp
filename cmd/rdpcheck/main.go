package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/x90skysn3k/grdp/client"
	"github.com/x90skysn3k/grdp/glog"
)

func main() {
	host := flag.String("host", "", "RDP host:port (e.g. 10.0.0.1:3389)")
	user := flag.String("user", "", "username (domain\\user or user)")
	pass := flag.String("pass", "", "password")
	timeout := flag.Duration("timeout", 30*time.Second, "connection timeout")
	verbose := flag.Bool("v", false, "verbose logging")
	flag.Parse()

	if *host == "" || *user == "" || *pass == "" {
		fmt.Fprintf(os.Stderr, "Usage: rdpcheck -host HOST:PORT -user USER -pass PASS [-timeout 30s] [-v]\n")
		os.Exit(1)
	}

	s := client.NewSetting()
	if *verbose {
		s.LogLevel = glog.TRACE
	}

	c := client.NewClient(*host, *user, *pass, client.TC_RDP, s)
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	start := time.Now()
	err := c.LoginAuthOnly(ctx)
	elapsed := time.Since(start)

	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL (%s): %v\n", elapsed.Round(time.Millisecond), err)
		os.Exit(1)
	}
	fmt.Printf("OK (%s): authentication successful\n", elapsed.Round(time.Millisecond))
}
