package proc

import (
	"fmt"
	"net"

	"github.com/lonelysadness/netmonitor/pkg/ebpf"
)

type ConnectionIdentifier struct {
	tracker *ebpf.ConnectionTracker
}

func NewConnectionIdentifier() (*ConnectionIdentifier, error) {
	tracker, err := ebpf.NewConnectionTracker()
	if err != nil {
		return nil, fmt.Errorf("failed to create connection tracker: %w", err)
	}

	return &ConnectionIdentifier{
		tracker: tracker,
	}, nil
}

func (ci *ConnectionIdentifier) Close() error {
	return ci.tracker.Close()
}

func (ci *ConnectionIdentifier) IdentifyConnection(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, protocol uint8) (*ConnectionDetails, error) {
	// For this example, we'll just look up by PID
	// In a full implementation, you'd want to match by IP/port as well
	info, err := ci.tracker.GetConnectionInfo(uint32(srcPort)) // Using srcPort as PID for demo
	if err != nil {
		return &ConnectionDetails{}, err
	}

	return &ConnectionDetails{
		PID:         int(info.PID),
		ProcessName: string(info.Comm[:]),
	}, nil
}
