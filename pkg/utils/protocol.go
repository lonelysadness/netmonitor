package utils

import "golang.org/x/sys/unix"

// protocolNames maps protocol numbers to their names.
var protocolNames = map[uint8]string{
    unix.IPPROTO_ICMP:    "ICMP",
    unix.IPPROTO_TCP:     "TCP",
    unix.IPPROTO_UDP:     "UDP",
    unix.IPPROTO_IPV6:    "IPv6",
    unix.IPPROTO_GRE:     "GRE",
    unix.IPPROTO_ESP:     "ESP",
    unix.IPPROTO_AH:      "AH",
    unix.IPPROTO_ICMPV6:  "ICMPv6",
    unix.IPPROTO_SCTP:    "SCTP",
    unix.IPPROTO_UDPLITE: "UDPLite",
}

// GetProtocolName returns the name of the protocol given its number.
func GetProtocolName(protocol uint8) string {
    if name, exists := protocolNames[protocol]; exists {
        return name
    }
    return "Unknown"
}

