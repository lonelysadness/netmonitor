package proc

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ParseProcNetFile parses the given /proc/net file to find the PID based on IP, port, and protocol
func ParseProcNetFile(ip string, port uint16, protocol int) (int, string, error) {
	file, err := getProcNetFile(ip, protocol)
	if err != nil {
		return 0, "", err
	}

	content, err := os.ReadFile(file)
	if err != nil {
		return 0, "", err
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		ipParsed, portParsed, err := parseProcNetFields(fields[1], ip)
		if err != nil {
			continue
		}

		if ipParsed == ip && uint16(portParsed) == port {
			pid, processName, err := findPidByInode(fields[9])
			if err != nil {
				return 0, "", err
			}
			return pid, processName, nil
		}
	}

	return 0, "", fmt.Errorf("no matching PID found for %s:%d/%d", ip, port, protocol)
}

func getProcNetFile(ip string, protocol int) (string, error) {
	isIPv6 := strings.Contains(ip, ":")
	if isIPv6 {
		switch protocol {
		case 6: // TCP
			return "/proc/net/tcp6", nil
		case 17: // UDP
			return "/proc/net/udp6", nil
		default:
			return "", fmt.Errorf("unsupported protocol: %d", protocol)
		}
	} else {
		switch protocol {
		case 6: // TCP
			return "/proc/net/tcp", nil
		case 17: // UDP
			return "/proc/net/udp", nil
		default:
			return "", fmt.Errorf("unsupported protocol: %d", protocol)
		}
	}
}

func parseProcNetFields(localAddress, ip string) (string, uint64, error) {
	parts := strings.Split(localAddress, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid address format")
	}

	var ipParsed string
	if strings.Contains(ip, ":") {
		ipParsed = parseHexIPv6(parts[0])
	} else {
		ipParsed = parseHexIP(parts[0])
	}
	portParsed, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return "", 0, err
	}

	return ipParsed, portParsed, nil
}

// parseHexIP converts a hexadecimal IPv4 string to a dotted decimal string
func parseHexIP(hex string) string {
	var ip [4]byte
	fmt.Sscanf(hex, "%02X%02X%02X%02X", &ip[3], &ip[2], &ip[1], &ip[0])
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

// parseHexIPv6 converts a hexadecimal IPv6 string to a colon-separated hexadecimal string
func parseHexIPv6(hex string) string {
	var ip [16]byte
	for i := 0; i < 16; i++ {
		fmt.Sscanf(hex[2*i:2*i+2], "%02X", &ip[i])
	}
	return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
		ip[0:2], ip[2:4], ip[4:6], ip[6:8],
		ip[8:10], ip[10:12], ip[12:14], ip[14:16])
}

// findPidByInode finds the PID and process name associated with a given inode by scanning /proc
func findPidByInode(inode string) (int, string, error) {
	// Check process cache first
	if info, exists := processCache.get(inode); exists {
		return info.PID, info.Name, nil
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, "", err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		pid := entry.Name()
		fdPath := fmt.Sprintf("/proc/%s/fd", pid)
		fdEntries, err := os.ReadDir(fdPath)
		if err != nil {
			continue
		}

		for _, fdEntry := range fdEntries {
			linkPath := fmt.Sprintf("/proc/%s/fd/%s", pid, fdEntry.Name())
			link, err := os.Readlink(linkPath)
			if err != nil {
				continue
			}

			if strings.Contains(link, inode) {
				commPath := fmt.Sprintf("/proc/%s/comm", pid)
				comm, err := os.ReadFile(commPath)
				if err != nil {
					return 0, "", err
				}

				processName := strings.TrimSpace(string(comm))
				pidInt, _ := strconv.Atoi(pid)

				// Update process cache
				processCache.Lock()
				processCache.processes[inode] = &ProcessInfo{
					PID:       pidInt,
					Name:      processName,
					UpdatedAt: time.Now(),
				}
				processCache.Unlock()

				return pidInt, processName, nil
			}
		}
	}

	return 0, "", fmt.Errorf("no PID found for inode: %s", inode)
}

// Add process cache
type ProcessCache struct {
	sync.RWMutex
	processes map[string]*ProcessInfo
	expiry    time.Time
}

type ProcessInfo struct {
	PID       int
	Name      string
	UpdatedAt time.Time
}

var (
	processCache = &ProcessCache{
		processes: make(map[string]*ProcessInfo),
	}
)

func (pc *ProcessCache) get(inode string) (*ProcessInfo, bool) {
	pc.RLock()
	defer pc.RUnlock()

	if pc.expiry.Before(time.Now()) {
		return nil, false
	}

	info, exists := pc.processes[inode]
	return info, exists
}

// ConnectionIdentifier provides methods to identify process information for network connections
type ConnectionIdentifier struct{}

// ConnectionDetails contains information about a network connection
type ConnectionDetails struct {
	PID         int
	ProcessName string
}

// NewConnectionIdentifier creates a new ConnectionIdentifier
func NewConnectionIdentifier() (*ConnectionIdentifier, error) {
	return &ConnectionIdentifier{}, nil
}

// IdentifyConnection looks up the process information for a given connection
func (ci *ConnectionIdentifier) IdentifyConnection(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, protocol uint8) (*ConnectionDetails, error) {
	// Convert protocol number to int
	protocolInt := int(protocol)

	// Use the existing ParseProcNetFile function
	pid, processName, err := ParseProcNetFile(srcIP.String(), srcPort, protocolInt)
	if err != nil {
		return &ConnectionDetails{}, err
	}

	return &ConnectionDetails{
		PID:         pid,
		ProcessName: processName,
	}, nil
}
