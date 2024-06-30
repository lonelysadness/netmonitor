package nfqueue

import (
    "encoding/binary"
    "fmt"
    "net"

    "github.com/chifflier/nfqueue-go/nfqueue"
    "github.com/lonelysadness/netmonitor/internal/geoip"
    "github.com.lonelysadness/netmonitor/internal/proc"
    "github.com/lonelysadness/netmonitor/pkg/utils"
    "golang.org/x/sys/unix"
)

func handleIPv4(packet []byte) (net.IP, net.IP, uint8) {
    ipHeader := packet[:20]
    srcIP := net.IP(ipHeader[12:16])
    dstIP := net.IP(ipHeader[16:20])
    protocol := ipHeader[9]
    return srcIP, dstIP, protocol
}

func handleIPv6(packet []byte) (net.IP, net.IP, uint8) {
    ipHeader := packet[:40]
    srcIP := net.IP(ipHeader[8:24])
    dstIP := net.IP(ipHeader[24:40])
    protocol := ipHeader[6]
    return srcIP, dstIP, protocol
}

func Callback(payload *nfqueue.Payload) int {
    packet := payload.Data
    var srcIP, dstIP net.IP
    var protocol uint8
    var srcPort, dstPort uint16

    // Determine if it's IPv4 or IPv6
    switch packet[0] >> 4 {
    case 4:
        srcIP, dstIP, protocol = handleIPv4(packet)
    case 6:
        srcIP, dstIP, protocol = handleIPv6(packet)
    default:
        fmt.Println("Unknown IP version")
        payload.SetVerdict(nfqueue.NF_ACCEPT)
        return 0
    }

    srcCountry := geoip.LookupCountry(srcIP)
    dstCountry := geoip.LookupCountry(dstIP)

    headerLength := 0
    if (packet[0] >> 4) == 4 {
        headerLength = int(packet[0]&0x0F) * 4
    } else if (packet[0] >> 4) == 6 {
        headerLength = 40
    }

    switch protocol {
    case unix.IPPROTO_TCP:
        if len(packet) >= headerLength+20 {
            tcpHeader := packet[headerLength : headerLength+20]
            srcPort = binary.BigEndian.Uint16(tcpHeader[0:2])
            dstPort = binary.BigEndian.Uint16(tcpHeader[2:4])
        }
    case unix.IPPROTO_UDP:
        if len(packet) >= headerLength+8 {
            udpHeader := packet[headerLength : headerLength+8]
            srcPort = binary.BigEndian.Uint16(udpHeader[0:2])
            dstPort = binary.BigEndian.Uint16(udpHeader[2:4])
        }
    case unix.IPPROTO_ICMP:
        if len(packet) >= headerLength+4 {
            handleICMP(packet, headerLength)
        }
    case unix.IPPROTO_ICMPV6:
        if len(packet) >= headerLength+4 {
            handleICMPv6(packet, headerLength)
        }
    }

    // Print source IP and country if applicable
    if srcCountry != "" {
        fmt.Printf("Source IP: %s:%d (%s)", srcIP, srcPort, srcCountry)
    } else {
        fmt.Printf("Source IP: %s:%d", srcIP, srcPort)
    }

    // Print destination IP and country if applicable
    if dstCountry != "" {
        fmt.Printf(", Destination IP: %s:%d (%s)", dstIP, dstPort, dstCountry)
    } else {
        fmt.Printf(", Destination IP: %s:%d", dstIP, dstPort)
    }

    // Print protocol
    fmt.Printf(", Protocol: %s", utils.GetProtocolName(protocol))

    pid, processName, err := proc.ParseProcNetFile(srcIP.String(), srcPort, int(protocol))
    if err == nil {
        fmt.Printf(", PID: %d, Process: %s", pid, processName)
    }

    fmt.Println()
    payload.SetVerdict(nfqueue.NF_ACCEPT)
    return 0
}

func handleICMP(packet []byte, headerLength int) {
    icmpHeader := packet[headerLength : headerLength+4]
    icmpType := icmpHeader[0]
    icmpCode := icmpHeader[1]
    fmt.Printf("ICMP Type: %d, ICMP Code: %d", icmpType, icmpCode)
}

func handleICMPv6(packet []byte, headerLength int) {
    icmpHeader := packet[headerLength : headerLength+4]
    icmpType := icmpHeader[0]
    icmpCode := icmpHeader[1]
    fmt.Printf("ICMPv6 Type: %d, ICMPv6 Code: %d", icmpType, icmpCode)
}

