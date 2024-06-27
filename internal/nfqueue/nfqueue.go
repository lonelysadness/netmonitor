package nfqueue

import (
	"github.com/chifflier/nfqueue-go/nfqueue"
	"golang.org/x/sys/unix"
)

type Queue struct {
	*nfqueue.Queue
}

func NewQueue(callback func(*nfqueue.Payload) int) (*Queue, error) {
	q := new(nfqueue.Queue)
	if err := q.Init(); err != nil {
		return nil, err
	}

	if err := q.Unbind(unix.AF_INET); err != nil {
		return nil, err
	}
	if err := q.Bind(unix.AF_INET); err != nil {
		return nil, err
	}
	if err := q.Unbind(unix.AF_INET6); err != nil {
		return nil, err
	}
	if err := q.Bind(unix.AF_INET6); err != nil {
		return nil, err
	}

	q.SetCallback(callback)

	if err := q.CreateQueue(0); err != nil {
		return nil, err
	}

	if err := q.SetMode(nfqueue.NFQNL_COPY_PACKET); err != nil {
		return nil, err
	}

	return &Queue{q}, nil
}

