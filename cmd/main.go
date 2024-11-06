package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"netmonitor/internal/geoip"
	"netmonitor/internal/iptables"
	"netmonitor/internal/logger"
	"netmonitor/internal/nfqueue"
)

func main() {
	mustInit := func(err error, msg string) {
		if err != nil {
			logger.Log.Fatalf("%s: %v", msg, err)
		}
	}

	logger.Log.Println("Starting netmonitor...")

	mustInit(geoip.Init("data/GeoLite2-Country.mmdb", "data/GeoLite2-ASN.mmdb"), "Error initializing GeoIP database")
	defer geoip.Close()

	// Initialize IPTables
	ipt, err := iptables.New()
	mustInit(err, "Error initializing iptables")

	// Setup IPTables rules
	mustInit(ipt.Setup(), "Error setting up iptables")
	defer ipt.Cleanup()

	qv4, err := nfqueue.NewQueue(17040, false, nfqueue.Callback)
	mustInit(err, "Error initializing nfqueue v4")
	defer qv4.Destroy()

	qv6, err := nfqueue.NewQueue(17060, false, nfqueue.Callback)
	mustInit(err, "Error initializing nfqueue v6")
	defer qv6.Destroy()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		logger.Log.Println("Shutting down...")
		qv4.Destroy()
		qv6.Destroy()
		ipt.Cleanup() // Use the instance method instead of package function
		os.Exit(0)
	}()

	qv4.Run(ctx)
	qv6.Run(ctx)
}
