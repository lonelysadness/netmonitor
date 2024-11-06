package nfqueue

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/florianl/go-nfqueue"
	"github.com/lonelysadness/netmonitor/internal/geoip"
	"github.com/lonelysadness/netmonitor/internal/logger"
	"github.com/lonelysadness/netmonitor/internal/proc"
	"github.com/lonelysadness/netmonitor/pkg/utils"
	"golang.org/x/sys/unix"
)

// ConnectionCache stores connection verdicts for faster processing
type ConnectionCache struct {
	sync.RWMutex
	verdicts    map[string]*CacheEntry
	cleanupDone chan struct{}
}

func init() {
	// Start the cleanup process
	ctx := context.Background()
	go connCache.startCleanup(ctx)
}

type CacheEntry struct {
	verdict int
	expiry  time.Time
}

var (
	connCache = &ConnectionCache{
		verdicts:    make(map[string]*CacheEntry),
		cleanupDone: make(chan struct{}),
	}
	cacheDuration  = 5 * time.Minute
	connIdentifier *proc.ConnectionIdentifier
)

func init() {
	var err error
	connIdentifier, err = proc.NewConnectionIdentifier()
	if err != nil {
		logger.Log.Fatalf("Failed to initialize connection identifier: %v", err)
	}
}

// Add periodic cleanup
func (c *ConnectionCache) startCleanup(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		defer close(c.cleanupDone)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.cleanup()
			}
		}
	}()
}

func (c *ConnectionCache) cleanup() {
	c.Lock()
	defer c.Unlock()
	now := time.Now()
	for key, entry := range c.verdicts {
		if now.After(entry.expiry) {
			delete(c.verdicts, key)
		}
	}
}

// getConnectionKey generates a unique key for a connection
func getConnectionKey(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, protocol uint8) string {
	return fmt.Sprintf("%s:%d->%s:%d:%d", srcIP, srcPort, dstIP, dstPort, protocol)
}

// getCachedVerdict checks if there's a cached verdict for this connection
func (c *ConnectionCache) getCachedVerdict(key string) (int, bool) {
	c.RLock()
	defer c.RUnlock()

	if entry, exists := c.verdicts[key]; exists {
		if time.Now().Before(entry.expiry) {
			return entry.verdict, true
		}
		// Clean up expired entry
		delete(c.verdicts, key)
	}
	return 0, false
}

// setCachedVerdict stores a verdict for a connection
func (c *ConnectionCache) setCachedVerdict(key string, verdict int) {
	c.Lock()
	defer c.Unlock()

	c.verdicts[key] = &CacheEntry{
		verdict: verdict,
		expiry:  time.Now().Add(cacheDuration),
	}
}

// handleIPv4 extracts IPv4 packet information
func handleIPv4(packet []byte) (net.IP, net.IP, uint8) {
	ipHeader := packet[:20]
	return net.IP(ipHeader[12:16]), net.IP(ipHeader[16:20]), ipHeader[9]
}

// handleIPv6 extracts IPv6 packet information
func handleIPv6(packet []byte) (net.IP, net.IP, uint8) {
	ipHeader := packet[:40]
	return net.IP(ipHeader[8:24]), net.IP(ipHeader[24:40]), ipHeader[6]
}

// parsePorts extracts source and destination ports
func parsePorts(packet []byte, protocol uint8, headerLength int) (uint16, uint16) {
	if len(packet) < headerLength+4 {
		return 0, 0
	}

	transportHeader := packet[headerLength:]
	switch protocol {
	case unix.IPPROTO_TCP, unix.IPPROTO_UDP:
		if len(transportHeader) >= 4 {
			return binary.BigEndian.Uint16(transportHeader[0:2]),
				binary.BigEndian.Uint16(transportHeader[2:4])
		}
	}
	return 0, 0
}

// Callback handles packet inspection and verdict decisions
func Callback(pkt Packet) int {
	packet := pkt.Data
	if len(packet) < 1 {
		return nfqueue.NfAccept
	}

	var srcIP, dstIP net.IP
	var protocol uint8
	var headerLength int

	// Determine IP version and extract header info
	switch packet[0] >> 4 {
	case 4:
		srcIP, dstIP, protocol = handleIPv4(packet)
		headerLength = int(packet[0]&0x0F) * 4
	case 6:
		srcIP, dstIP, protocol = handleIPv6(packet)
		headerLength = 40
	default:
		logger.Log.Printf("Unknown IP version for packet ID: %s", pkt.ID())
		return nfqueue.NfAccept
	}

	srcPort, dstPort := parsePorts(packet, protocol, headerLength)
	connKey := getConnectionKey(srcIP, srcPort, dstIP, dstPort, protocol)

	// Check cached verdict
	if verdict, exists := connCache.getCachedVerdict(connKey); exists {
		return verdict
	}

	// Get connection details
	country := geoip.LookupCountry(dstIP)
	org, asn, _ := geoip.LookupASN(dstIP)

	// Use the new connection identifier
	connDetails, err := connIdentifier.IdentifyConnection(srcIP, srcPort, dstIP, dstPort, protocol)
	if err != nil {
		logger.Log.Printf("Failed to identify connection: %v", err)
	}

	// Log connection details
	logConnection(srcIP, srcPort, dstIP, dstPort, protocol, country, org, asn, connDetails.PID, connDetails.ProcessName)

	// TODO: Implement rule matching logic here
	// For now, we'll accept everything but you should add:
	// 1. Rule matching based on process
	// 2. User-defined rules
	// 3. Geographic restrictions
	// 4. Rate limiting
	verdict := MarkAcceptAlways // Use firewall mark instead of nfqueue.NfAccept

	// Cache the verdict
	connCache.setCachedVerdict(connKey, verdict)

	// Mark the packet before returning verdict
	if err := pkt.mark(verdict); err != nil {
		logger.Log.Printf("Failed to mark packet: %v", err)
		return MarkAccept // Fallback to basic accept mark if marking fails
	}

	return verdict
}

// logConnection logs connection details to file and terminal
func logConnection(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16,
	protocol uint8, country, org string, asn uint, pid int, processName string) {

	var logMsg strings.Builder

	// Format basic connection info with ANSI colors for terminal
	logMsg.WriteString("\033[1;36m") // Cyan color for connection details
	fmt.Fprintf(&logMsg, "%s:%d -> %s:%d [%s]",
		srcIP, srcPort, dstIP, dstPort, utils.GetProtocolName(protocol))
	logMsg.WriteString("\033[0m") // Reset color

	// Add geographic info
	if country != "" {
		logMsg.WriteString("\033[1;33m") // Yellow for country
		fmt.Fprintf(&logMsg, " Country: %s", country)
		logMsg.WriteString("\033[0m")
	}

	// Add organizational info
	if org != "" {
		logMsg.WriteString("\033[1;32m") // Green for org
		fmt.Fprintf(&logMsg, " Org: %s", org)
		logMsg.WriteString("\033[0m")
	}
	if asn != 0 {
		fmt.Fprintf(&logMsg, " ASN: %d", asn)
	}

	// Add process info
	if pid != 0 {
		logMsg.WriteString("\033[1;35m") // Magenta for process
		fmt.Fprintf(&logMsg, " Process: %s (PID: %d)", processName, pid)
		logMsg.WriteString("\033[0m")
	}

	logString := logMsg.String()

	// Log to file
	logger.Log.Println(logString)

	// Print to terminal with timestamp
	timestamp := time.Now().Format("15:04:05")
	fmt.Printf("[%s] %s\n", timestamp, logString)
}
