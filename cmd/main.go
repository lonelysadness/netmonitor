package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/lonelysadness/netmonitor/internal/geoip"
	"github.com/lonelysadness/netmonitor/internal/iptables"
	"github.com/lonelysadness/netmonitor/internal/logger"
	"github.com/lonelysadness/netmonitor/internal/nfqueue"
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

	mustInit(iptables.Setup(), "Error setting up iptables")
	defer iptables.Cleanup()

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
		iptables.Cleanup()
		os.Exit(0)
	}()

	qv4.Run(ctx)
	qv6.Run(ctx)
}
