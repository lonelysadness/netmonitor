package proc

import (
    "fmt"
    "io/ioutil"
    "os"
    "strconv"
    "strings"
)

// ParseProcNetFile parses the given /proc/net file to find the PID based on IP, port, and protocol
func ParseProcNetFile(ip string, port uint16, protocol int) (int, string, error) {
    var file string
    isIPv6 := strings.Contains(ip, ":")
    if isIPv6 {
        switch protocol {
        case 6: // TCP
            file = "/proc/net/tcp6"
        case 17: // UDP
            file = "/proc/net/udp6"
        default:
            return 0, "", fmt.Errorf("unsupported protocol: %d", protocol)
        }
    } else {
        switch protocol {
        case 6: // TCP
            file = "/proc/net/tcp"
        case 17: // UDP
            file = "/proc/net/udp"
        default:
            return 0, "", fmt.Errorf("unsupported protocol: %d", protocol)
        }
    }

    content, err := ioutil.ReadFile(file)
    if err != nil {
        return 0, "", err
    }

    lines := strings.Split(string(content), "\n")
    for _, line := range lines {
        fields := strings.Fields(line)
        if len(fields) < 10 {
            continue
        }

        localAddress := fields[1]
        parts := strings.Split(localAddress, ":")
        if len(parts) != 2 {
            continue
        }

        ipHex := parts[0]
        portHex := parts[1]

        var ipParsed string
        if isIPv6 {
            ipParsed = parseHexIPv6(ipHex)
        } else {
            ipParsed = parseHexIP(ipHex)
        }
        portParsed, _ := strconv.ParseUint(portHex, 16, 16)

        if ipParsed == ip && uint16(portParsed) == port {
            inode := fields[9]
            pid, processName, err := findPidByInode(inode)
            if err != nil {
                return 0, "", err
            }
            return pid, processName, nil
        }
    }

    return 0, "", fmt.Errorf("no matching PID found for %s:%d/%d", ip, port, protocol)
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
    entries, err := ioutil.ReadDir("/proc")
    if err != nil {
        return 0, "", err
    }

    for _, entry := range entries {
        if !entry.IsDir() {
            continue
        }

        pid := entry.Name()
        fdPath := fmt.Sprintf("/proc/%s/fd", pid)
        fdEntries, err := ioutil.ReadDir(fdPath)
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
                comm, err := ioutil.ReadFile(commPath)
                if err != nil {
                    return 0, "", err
                }

                processName := strings.TrimSpace(string(comm))
                pidInt, _ := strconv.Atoi(pid)
                return pidInt, processName, nil
            }
        }
    }

    return 0, "", fmt.Errorf("no PID found for inode: %s", inode)
}

