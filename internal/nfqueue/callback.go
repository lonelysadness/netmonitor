package nfqueue

import (
    "encoding/binary"
    "fmt"
    "net"

    "github.com/florianl/go-nfqueue"
    "github.com/lonelysadness/netmonitor/internal/geoip"
    "github.com/lonelysadness/netmonitor/internal/logger"
    "github.com/lonelysadness/netmonitor/internal/proc"
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

func parsePorts(packet []byte, protocol uint8, headerLength int) (uint16, uint16) {
    var srcPort, dstPort uint16
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
    }
    return srcPort, dstPort
}

func isLocalIP(ip net.IP) bool {
    if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
        return true
    }
    return false
}

func Callback(pkt Packet) int {
    packet := pkt.Data
    var srcIP, dstIP net.IP
    var protocol uint8

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

    var remoteIP net.IP
    if isLocalIP(srcIP) {
        remoteIP = dstIP
    } else {
        remoteIP = srcIP
    }

    country := geoip.LookupCountry(remoteIP)
    org, asn, _ := geoip.LookupASN(remoteIP)

    headerLength := 0
    if (packet[0] >> 4) == 4 {
        headerLength = int(packet[0]&0x0F) * 4
    } else if (packet[0] >> 4) == 6 {
        headerLength = 40
    }

    srcPort, dstPort := parsePorts(packet, protocol, headerLength)

    output := fmt.Sprintf("%s:%d", srcIP, srcPort)
    if country != "" {
        output += fmt.Sprintf(" (%s)", country)
    }

    output += fmt.Sprintf(" -> %s:%d", dstIP, dstPort)
    if country != "" {
        output += fmt.Sprintf(" (%s)", country)
    }

    output += fmt.Sprintf(" | %s", utils.GetProtocolName(protocol))

    if org != "" {
        output += fmt.Sprintf(", Org: %s", org)
    }

    if asn != 0 {
        output += fmt.Sprintf(", ASN: %d", asn)
    }

    if pid, processName, err := proc.ParseProcNetFile(srcIP.String(), srcPort, int(protocol)); err == nil {
        output += fmt.Sprintf(", PID: %d, Process: %s", pid, processName)
    }

    fmt.Println(output)

    // Use the mark function to set packet marks
    pkt.mark(MarkAcceptAlways)

    return 0
}

