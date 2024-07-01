package nfqueue

import (
    "encoding/binary"
    "fmt"
    "net"

    "github.com/florianl/go-nfqueue"
    "github.com/lonelysadness/netmonitor/internal/geoip"
    "github.com/lonelysadness/netmonitor/internal/logger"
    "github.com/lonelysadness/netmonitor/internal/proc"
    "golang.org/x/sys/unix"
)

const (
    ProtocolICMP   = 1
    ProtocolICMPv6 = 58
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

func handleICMP(packet []byte, headerLength int) (int, int) {
    icmpHeader := packet[headerLength : headerLength+4]
    icmpType := int(icmpHeader[0])
    icmpCode := int(icmpHeader[1])
    return icmpType, icmpCode
}

func handleICMPv6(packet []byte, headerLength int) (int, int) {
    icmpHeader := packet[headerLength : headerLength+4]
    icmpType := int(icmpHeader[0])
    icmpCode := int(icmpHeader[1])
    return icmpType, icmpCode
}

func Callback(pkt Packet) int {
    packet := pkt.Data
    var srcIP, dstIP net.IP
    var protocol uint8
    var srcPort, dstPort uint16

    switch packet[0] >> 4 {
    case 4:
        srcIP, dstIP, protocol = handleIPv4(packet)
    case 6:
        srcIP, dstIP, protocol = handleIPv6(packet)
    default:
        logger.Log.Println("Unknown IP version")
        pkt.queue.getNfq().SetVerdict(pkt.pktID, nfqueue.NfAccept)
        return 0
    }

    pkt.SrcIP = srcIP
    pkt.DstIP = dstIP
    pkt.Protocol = protocol

    srcCountry := geoip.LookupCountry(srcIP)
    dstCountry := geoip.LookupCountry(dstIP)

    headerLength := 0
    if (packet[0] >> 4) == 4 {
        headerLength = int(packet[0]&0x0F) * 4
    } else if (packet[0] >> 4) == 6 {
        headerLength = 40
    }

    var icmpType, icmpCode int
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
            icmpType, icmpCode = handleICMP(packet, headerLength)
        }
    case unix.IPPROTO_ICMPV6:
        if len(packet) >= headerLength+4 {
            icmpType, icmpCode = handleICMPv6(packet, headerLength)
        }
    }

    output := fmt.Sprintf("%s:%d", srcIP, srcPort)
    if srcCountry != "" {
        output += fmt.Sprintf(" (%s)", srcCountry)
    }

    output += fmt.Sprintf(" -> %s:%d", dstIP, dstPort)
    if dstCountry != "" {
        output += fmt.Sprintf(" (%s)", dstCountry)
    }

    output += fmt.Sprintf(" | Protocol: %d", protocol)

    if pid, processName, err := proc.ParseProcNetFile(srcIP.String(), srcPort, int(protocol)); err == nil {
        output += fmt.Sprintf(", PID: %d, Process: %s", pid, processName)
    }

    if protocol == ProtocolICMP || protocol == ProtocolICMPv6 {
        output += fmt.Sprintf(", ICMP Type: %d, ICMP Code: %d", icmpType, icmpCode)
    }

    fmt.Println(output)

    // Use the mark function to set packet marks
    pkt.mark(MarkAcceptAlways) // You can use different marks based on conditions

    return 0
}

