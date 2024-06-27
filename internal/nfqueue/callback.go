package nfqueue

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/chifflier/nfqueue-go/nfqueue"
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

func handleTCP(packet []byte, headerLength int) {
	tcpHeader := packet[headerLength : headerLength+20]
	srcPort := binary.BigEndian.Uint16(tcpHeader[0:2])
	dstPort := binary.BigEndian.Uint16(tcpHeader[2:4])
	fmt.Printf("Source Port: %d, Destination Port: %d", srcPort, dstPort)
}

func handleUDP(packet []byte, headerLength int) {
	udpHeader := packet[headerLength : headerLength+8]
	srcPort := binary.BigEndian.Uint16(udpHeader[0:2])
	dstPort := binary.BigEndian.Uint16(udpHeader[2:4])
	fmt.Printf("Source Port: %d, Destination Port: %d", srcPort, dstPort)
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

func Callback(payload *nfqueue.Payload) int {
	packet := payload.Data
	var srcIP, dstIP net.IP
	var protocol uint8

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

	fmt.Printf("Source IP: %s, Destination IP: %s, Protocol: %s, ", srcIP, dstIP, utils.GetProtocolName(protocol))

	headerLength := 0
	if (packet[0] >> 4) == 4 {
		headerLength = int(packet[0]&0x0F) * 4
	} else if (packet[0] >> 4) == 6 {
		headerLength = 40
	}

	switch protocol {
	case unix.IPPROTO_TCP:
		if len(packet) >= headerLength+20 {
			handleTCP(packet, headerLength)
		}
	case unix.IPPROTO_UDP:
		if len(packet) >= headerLength+8 {
			handleUDP(packet, headerLength)
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

	fmt.Println()
	payload.SetVerdict(nfqueue.NF_ACCEPT)
	return 0
}

