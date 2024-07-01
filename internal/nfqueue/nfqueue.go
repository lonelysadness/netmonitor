package nfqueue

import (
    "context"
    "log"
    "strings"
    "sync/atomic"
    "time"

    "github.com/florianl/go-nfqueue"
    "github.com/tevino/abool"
    "golang.org/x/sys/unix"
)

type Queue struct {
    id                   uint16
    afFamily             uint8
    nf                   atomic.Value
    packets              chan Packet
    cancelSocketCallback context.CancelFunc
    restart              chan struct{}
    pendingVerdicts      uint64
    verdictCompleted     chan struct{}
}

type Packet struct {
    pktID          uint32
    queue          *Queue
    verdictSet     chan struct{}
    verdictPending *abool.AtomicBool
    Base           nfqueue.Attribute
}

func NewQueue(qid uint16, v6 bool, callback func(Packet) int) (*Queue, error) {
    afFamily := unix.AF_INET
    if v6 {
        afFamily = unix.AF_INET6
    }

    ctx, cancel := context.WithCancel(context.Background())
    q := &Queue{
        id:                   qid,
        afFamily:             uint8(afFamily),
        restart:              make(chan struct{}, 1),
        packets:              make(chan Packet, 5000),
        cancelSocketCallback: cancel,
        verdictCompleted:     make(chan struct{}, 1),
    }

    if err := q.open(ctx, callback); err != nil {
        return nil, err
    }

    go q.monitor(ctx, callback)
    return q, nil
}

func (q *Queue) open(ctx context.Context, callback func(Packet) int) error {
    cfg := &nfqueue.Config{
        NfQueue:      q.id,
        MaxPacketLen: 1600,
        MaxQueueLen:  0xffff,
        AfFamily:     q.afFamily,
        Copymode:     nfqueue.NfQnlCopyPacket,
        ReadTimeout:  2000 * time.Millisecond,
        WriteTimeout: 2000 * time.Millisecond,
    }

    nf, err := nfqueue.Open(cfg)
    if err != nil {
        return err
    }

    if err := nf.RegisterWithErrorFunc(ctx, q.packetHandler(ctx, callback), q.handleError); err != nil {
        _ = nf.Close()
        return err
    }

    q.nf.Store(nf)
    return nil
}

func (q *Queue) packetHandler(ctx context.Context, callback func(Packet) int) func(nfqueue.Attribute) int {
    return func(attrs nfqueue.Attribute) int {
        if attrs.PacketID == nil {
            return 0
        }

        pkt := Packet{
            pktID:          *attrs.PacketID,
            queue:          q,
            verdictSet:     make(chan struct{}),
            verdictPending: abool.New(),
            Base:           attrs,
        }

        select {
        case q.packets <- pkt:
            go callback(pkt)
        case <-ctx.Done():
            return 0
        case <-time.After(time.Second):
            log.Printf("nfqueue: failed to queue packet, slowing down intake")
            time.Sleep(10 * time.Millisecond) // Introduce a small delay
            select {
            case q.packets <- pkt:
                go callback(pkt)
            case <-ctx.Done():
                return 0
            case <-time.After(time.Second):
                log.Printf("nfqueue: failed to queue packet again, dropping")
            }
        }

        return 0
    }
}

func (q *Queue) handleError(e error) int {
    if opError, ok := e.(interface{ Timeout() bool; Temporary() bool }); ok {
        if opError.Timeout() || opError.Temporary() {
            for atomic.LoadUint64(&q.pendingVerdicts) > 0 {
                <-q.verdictCompleted
            }
            return 0
        }
    }

    if !strings.HasSuffix(e.Error(), "use of closed file") {
        log.Printf("nfqueue: encountered error while receiving packets: %s\n", e.Error())
    }

    if nf := q.getNfq(); nf != nil {
        _ = nf.Con.Close()
    }

    q.restart <- struct{}{}
    return 1
}

func (q *Queue) getNfq() *nfqueue.Nfqueue {
    return q.nf.Load().(*nfqueue.Nfqueue)
}

func (q *Queue) monitor(ctx context.Context, callback func(Packet) int) {
    for {
        select {
        case <-ctx.Done():
            return
        case <-q.restart:
            for {
                err := q.open(ctx, callback)
                if err == nil {
                    break
                }
                log.Printf("Failed to open nfqueue: %s", err)
                time.Sleep(100 * time.Millisecond)
            }
        }
    }
}

func (q *Queue) Run(ctx context.Context) {
    <-ctx.Done()
    q.Destroy()
}

func (q *Queue) Destroy() {
    q.cancelSocketCallback()
    if nf := q.getNfq(); nf != nil {
        if err := nf.Close(); err != nil {
            log.Printf("nfqueue: failed to close queue %d: %s", q.id, err)
        }
    }
}

