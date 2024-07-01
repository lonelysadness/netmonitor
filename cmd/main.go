package main

import (
    "context"
    "fmt"
    "log"
    "os"
    "os/signal"
    "sync"
    "syscall"
    "net/http"

    "github.com/gin-gonic/gin"
    "github.com/lonelysadness/netmonitor/internal/geoip"
    "github.com/lonelysadness/netmonitor/internal/iptables"
    "github.com/lonelysadness/netmonitor/internal/nfqueue"
    _ "github.com/lonelysadness/netmonitor/internal/logger" // import logger to initialize it
)

var (
    connections map[string][]nfqueue.ConnectionDetails
    mutex       sync.Mutex
)

func main() {
    // Initialize GeoIP databases
    if err := geoip.Init("data/GeoLite2-Country.mmdb", "data/GeoLite2-ASN.mmdb"); err != nil {
        log.Fatalf("Error initializing GeoIP databases: %v", err)
    }
    defer geoip.Close()

    // Setup iptables
    if err := iptables.Setup(); err != nil {
        log.Fatalf("Error setting up iptables: %v", err)
    }
    defer iptables.Cleanup()

    // Initialize connections map
    connections = make(map[string][]nfqueue.ConnectionDetails)
    nfqueue.Init(connections, &mutex)

    // Initialize nfqueue
    q, err := nfqueue.NewQueue(0, false, nfqueue.Callback)
    if err != nil {
        log.Fatalf("Error initializing nfqueue: %v", err)
    }
    defer q.Destroy()

    // Setup context for signal handling
    ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer stop()

    // Graceful shutdown handling
    go func() {
        <-ctx.Done()
        fmt.Println("Shutting down...")
        q.Destroy()
        iptables.Cleanup()
        os.Exit(0)
    }()

    // Start the nfqueue handler
    go q.Run(ctx)

    // Start the HTTP server
    go startHTTPServer()

    // Keep the main function running
    <-ctx.Done()
}

func startHTTPServer() {
    router := gin.Default()
    router.GET("/connections", getConnections)
    if err := router.Run(":4000"); err != nil {
        log.Fatalf("Failed to start HTTP server: %v", err)
    }
}

func getConnections(c *gin.Context) {
    mutex.Lock()
    defer mutex.Unlock()
    log.Printf("Connections: %+v\n", connections) // Log the connections to verify the data
    c.JSON(http.StatusOK, connections)
}

