package nfqueue

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/florianl/go-nfqueue"
	"github.com/lonelysadness/netmonitor/internal/logger"
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
	stats                *QueueStats
	bufferPool           *sync.Pool
}

type QueueStats struct {
	sync.Mutex
	PacketsProcessed uint64
	PacketsDropped   uint64
	ProcessingTime   time.Duration
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
		stats:                &QueueStats{},
		bufferPool: &sync.Pool{
			New: func() interface{} {
				return make([]byte, 65535)
			},
		},
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
		logger.Log.Printf("nfqueue: failed to open queue %d: %s", q.id, err)
		return err
	}

	if err := nf.RegisterWithErrorFunc(ctx, q.packetHandler(ctx, callback), q.handleError); err != nil {
		logger.Log.Printf("nfqueue: failed to register error function for queue %d: %s", q.id, err)
		_ = nf.Close()
		return err
	}

	q.nf.Store(nf)
	return nil
}

func (q *Queue) packetHandler(ctx context.Context, callback func(Packet) int) func(nfqueue.Attribute) int {
	return func(attrs nfqueue.Attribute) int {
		start := time.Now()
		defer func() {
			q.stats.Lock()
			q.stats.ProcessingTime += time.Since(start)
			q.stats.PacketsProcessed++
			q.stats.Unlock()
		}()

		if attrs.PacketID == nil {
			return 0
		}

		pkt := Packet{
			pktID:          *attrs.PacketID,
			queue:          q,
			verdictSet:     make(chan struct{}),
			verdictPending: abool.New(),
			Data:           *attrs.Payload, // Dereference the pointer to get the byte slice
		}

		select {
		case q.packets <- pkt:
			go callback(pkt)
		case <-ctx.Done():
			return 0
		case <-time.After(time.Second):
			logger.Log.Printf("nfqueue: failed to queue packet, slowing down intake")
			time.Sleep(10 * time.Millisecond)
			select {
			case q.packets <- pkt:
				go callback(pkt)
			case <-ctx.Done():
				return 0
			case <-time.After(time.Second):
				logger.Log.Printf("nfqueue: failed to queue packet again, dropping")
			}
		}

		return 0
	}
}

func (q *Queue) handleError(e error) int {
	if opError, ok := e.(interface {
		Timeout() bool
		Temporary() bool
	}); ok && (opError.Timeout() || opError.Temporary()) {
		for atomic.LoadUint64(&q.pendingVerdicts) > 0 {
			<-q.verdictCompleted
		}
		return 0
	}

	if !strings.HasSuffix(e.Error(), "use of closed file") {
		logger.Log.Printf("nfqueue: encountered error while receiving packets: %s\n", e.Error())
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
				logger.Log.Printf("Failed to open nfqueue: %s", err)
				time.Sleep(100 * time.Millisecond)
			}
			logger.Log.Println("Reopened nfqueue")
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
			logger.Log.Printf("nfqueue: failed to close queue %d: %s", q.id, err)
		}
	}
}
