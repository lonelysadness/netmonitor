package nfqueue

import (
    "errors"
    "fmt"
    "net"
    "sync/atomic"

    "github.com/florianl/go-nfqueue"
    "github.com/tevino/abool"
    "golang.org/x/sys/unix"
    "github.com/lonelysadness/netmonitor/internal/logger"
)

type Packet struct {
    Base
    pktID          uint32
    queue          *Queue
    verdictSet     chan struct{}
    verdictPending *abool.AtomicBool
    Data           []byte
    SrcIP          net.IP
    DstIP          net.IP
    Protocol       uint8
}

func (pkt *Packet) ID() string {
    return fmt.Sprintf("pkt:%d qid:%d", pkt.pktID, pkt.queue.id)
}

func (pkt *Packet) LoadPacketData() error {
    return nil
}

func (pkt *Packet) mark(mark int) error {
    if pkt.verdictPending.SetToIf(false, true) {
        defer close(pkt.verdictSet)
        return pkt.setMark(mark)
    }
    return errors.New("verdict already set")
}

func (pkt *Packet) setMark(mark int) error {
    atomic.AddUint64(&pkt.queue.pendingVerdicts, 1)
    defer func() {
        atomic.AddUint64(&pkt.queue.pendingVerdicts, ^uint64(0))
        select {
        case pkt.queue.verdictCompleted <- struct{}{}:
        default:
        }
    }()

    for {
        if err := pkt.queue.getNfq().SetVerdictWithMark(pkt.pktID, nfqueue.NfAccept, mark); err != nil {
            if opErr, ok := err.(interface {
                Timeout() bool
                Temporary() bool
            }); ok {
                if opErr.Timeout() || opErr.Temporary() {
                    continue
                }
            }

            logger.Log.Printf("nfqueue: failed to set verdict %s for %s (%s -> %s): %s",
                markToString(mark), pkt.ID(), pkt.SrcIP, pkt.DstIP, err)
            return err
        }
        break
    }
    return nil
}

func (pkt *Packet) Accept() error {
    return pkt.mark(MarkAccept)
}

func (pkt *Packet) Block() error {
    if pkt.Protocol == unix.IPPROTO_ICMP {
        return pkt.mark(MarkDrop)
    }
    return pkt.mark(MarkBlock)
}

func (pkt *Packet) Drop() error {
    return pkt.mark(MarkDrop)
}

func (pkt *Packet) PermanentAccept() error {
    if !pkt.Base.Inbound && pkt.DstIP.IsLoopback() {
        return pkt.Accept()
    }
    return pkt.mark(MarkAcceptAlways)
}

func (pkt *Packet) PermanentBlock() error {
    if pkt.Protocol == unix.IPPROTO_ICMP || pkt.Protocol == unix.IPPROTO_ICMPV6 {
        return pkt.mark(MarkDropAlways)
    }
    return pkt.mark(MarkBlockAlways)
}

func (pkt *Packet) PermanentDrop() error {
    return pkt.mark(MarkDropAlways)
}

func (pkt *Packet) RerouteToNameserver() error {
    return pkt.mark(MarkRerouteNS)
}

