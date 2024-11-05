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

// Use a more efficient mark lookup
var markDescriptions = map[int]string{
	MarkAccept:       "Accept",
	MarkBlock:        "Block",
	MarkDrop:         "Drop",
	MarkAcceptAlways: "AcceptAlways",
	MarkBlockAlways:  "BlockAlways",
	MarkDropAlways:   "DropAlways",
	MarkRerouteNS:    "RerouteNS",
}

func markToString(mark int) string {
	if desc, ok := markDescriptions[mark]; ok {
		return desc
	}
	return "unknown"
}
