package main

import (
    "context"
    "fmt"
    "log"
    "os"
    "os/signal"
    "syscall"

    "github.com/lonelysadness/netmonitor/internal/geoip"
    "github.com/lonelysadness/netmonitor/internal/iptables"
    "github.com/lonelysadness/netmonitor/internal/nfqueue"
    _ "github.com/lonelysadness/netmonitor/internal/logger" // import logger to initialize it
)

func main() {
    if err := geoip.Init("data/GeoLite2-Country.mmdb"); err != nil {
        log.Fatalf("Error initializing GeoIP database: %v", err)
    }
    defer geoip.Close()

    if err := iptables.Setup(); err != nil {
        log.Fatalf("Error setting up iptables: %v", err)
    }
    defer iptables.Cleanup()

    q, err := nfqueue.NewQueue(0, false, nfqueue.Callback)
    if err != nil {
        log.Fatalf("Error initializing nfqueue: %v", err)
    }
    defer q.Destroy()

    ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer stop()

    go func() {
        <-ctx.Done()
        fmt.Println("Shutting down...")
        q.Destroy()
        iptables.Cleanup()
        os.Exit(0)
    }()

    q.Run(ctx)
}

