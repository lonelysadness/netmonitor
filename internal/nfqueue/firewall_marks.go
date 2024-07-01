package nfqueue

const (
	MarkAccept       = 1700
	MarkBlock        = 1701
	MarkDrop         = 1702
	MarkAcceptAlways = 1710
	MarkBlockAlways  = 1711
	MarkDropAlways   = 1712
	MarkRerouteNS    = 1799
)

func markToString(mark int) string {
	switch mark {
	case MarkAccept:
		return "Accept"
	case MarkBlock:
		return "Block"
	case MarkDrop:
		return "Drop"
	case MarkAcceptAlways:
		return "AcceptAlways"
	case MarkBlockAlways:
		return "BlockAlways"
	case MarkDropAlways:
		return "DropAlways"
	case MarkRerouteNS:
		return "RerouteNS"
	}
	return "unknown"
}

