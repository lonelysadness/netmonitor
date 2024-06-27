package utils

import "golang.org/x/sys/unix"

// GetProtocolName returns the name of the protocol given its number.
func GetProtocolName(protocol uint8) string {
	switch protocol {
	case unix.IPPROTO_ICMP:
		return "ICMP"
	case unix.IPPROTO_TCP:
		return "TCP"
	case unix.IPPROTO_UDP:
		return "UDP"
	case unix.IPPROTO_IPV6:
		return "IPv6"
	case unix.IPPROTO_GRE:
		return "GRE"
	case unix.IPPROTO_ESP:
		return "ESP"
	case unix.IPPROTO_AH:
		return "AH"
	case unix.IPPROTO_ICMPV6:
		return "ICMPv6"
	case unix.IPPROTO_SCTP:
		return "SCTP"
	case unix.IPPROTO_UDPLITE:
		return "UDPLite"
	default:
		return "Unknown"
	}
}

