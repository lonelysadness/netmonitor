package nfqueue

import (
    "encoding/binary"
    "net"
    "sync"
    "time"
    "fmt"

    "github.com/florianl/go-nfqueue"
    "github.com/lonelysadness/netmonitor/internal/geoip"
    "github.com/lonelysadness/netmonitor/internal/logger"
    "github.com/lonelysadness/netmonitor/internal/proc"
    "github.com/lonelysadness/netmonitor/pkg/utils"
    "golang.org/x/sys/unix"
)

var (
    connections map[string][]ConnectionDetails
    mutex       *sync.Mutex
)

type ConnectionDetails struct {
    SourceIP           string
    DestinationIP      string
    Protocol           string
    Process            string
    PID                int
    SourceCountry      string
    DestinationCountry string
    ASN                string
    Org                string
    Domain             string // Added field for domain name
    Encrypted          bool
    Tunnel             bool
    StartTime          time.Time
    EndTime            time.Time
    LocalAddress       string
    RemoteAddress      string
    Direction          string
}

func Init(connMap map[string][]ConnectionDetails, mtx *sync.Mutex) {
    connections = connMap
    mutex = mtx
}

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

func Callback(pkt Packet) int {
    packet := *pkt.Base.Payload
    var srcIP, dstIP net.IP
    var protocol uint8
    var srcPort, dstPort uint16

    startTime := time.Now()

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

    srcCountry := geoip.LookupCountry(srcIP)
    dstCountry := geoip.LookupCountry(dstIP)
    asn, org := geoip.LookupASN(dstIP)
    domain := geoip.LookupDomain(dstIP) // Perform domain lookup

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
    }

    encrypted := false
    if dstPort == 443 {
        encrypted = true
    }

    tunnel := false
    if protocol == unix.IPPROTO_IPIP || protocol == unix.IPPROTO_GRE {
        tunnel = true
    }

    direction := "Outgoing"
    if srcIP.IsPrivate() && !dstIP.IsPrivate() {
        direction = "Outgoing"
    } else if !srcIP.IsPrivate() && dstIP.IsPrivate() {
        direction = "Incoming"
    }

    pid, processName, err := proc.ParseProcNetFile(srcIP.String(), srcPort, int(protocol))
    if err != nil {
        processName = "Unknown"
    }

    connection := ConnectionDetails{
        SourceIP:           srcIP.String(),
        DestinationIP:      dstIP.String(),
        Protocol:           utils.GetProtocolName(protocol),
        Process:            processName,
        PID:                pid,
        SourceCountry:      srcCountry,
        DestinationCountry: dstCountry,
        ASN:                asn,
        Org:                org,
        Domain:             domain, // Add domain name to connection details
        Encrypted:          encrypted,
        Tunnel:             tunnel,
        StartTime:          startTime,
        LocalAddress:       fmt.Sprintf("%s:%d", srcIP.String(), srcPort),
        RemoteAddress:      fmt.Sprintf("%s:%d", dstIP.String(), dstPort),
        Direction:          direction,
    }

    mutex.Lock()
    connections[processName] = append(connections[processName], connection)
    mutex.Unlock()

    pkt.queue.getNfq().SetVerdict(pkt.pktID, nfqueue.NfAccept)
    return 0
}

