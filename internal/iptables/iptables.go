package iptables

import (
	"fmt"
	"sync"

	"github.com/coreos/go-iptables/iptables"
	"github.com/hashicorp/go-multierror"
)

// IPTables holds the configuration and state for iptables management
type IPTables struct {
	ipt4     *iptables.IPTables
	ipt6     *iptables.IPTables
	v4Config *chainConfig
	v6Config *chainConfig
	mutex    sync.Mutex
}

type chainConfig struct {
	chains []chain
	rules  []rule
	once   []rule
}

type chain struct {
	table string
	name  string
}

type rule struct {
	table string
	chain string
	args  []string
}

// New creates a new IPTables instance
func New() (*IPTables, error) {
	ipt4, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize IPv4 tables: %w", err)
	}

	ipt6, err := iptables.NewWithProtocol(iptables.ProtocolIPv6)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize IPv6 tables: %w", err)
	}

	return &IPTables{
		ipt4:     ipt4,
		ipt6:     ipt6,
		v4Config: getIPv4Config(),
		v6Config: getIPv6Config(),
	}, nil
}

func (ipt *IPTables) Setup() error {
	ipt.mutex.Lock()
	defer ipt.mutex.Unlock()

	if err := ipt.activate(ipt.ipt4, ipt.v4Config); err != nil {
		return fmt.Errorf("failed to setup IPv4 rules: %w", err)
	}

	if err := ipt.activate(ipt.ipt6, ipt.v6Config); err != nil {
		return fmt.Errorf("failed to setup IPv6 rules: %w", err)
	}

	return nil
}

func (ipt *IPTables) Cleanup() error {
	ipt.mutex.Lock()
	defer ipt.mutex.Unlock()

	var result error
	if err := ipt.deactivate(ipt.ipt4, ipt.v4Config); err != nil {
		result = multierror.Append(result, fmt.Errorf("IPv4 cleanup failed: %w", err))
	}

	if err := ipt.deactivate(ipt.ipt6, ipt.v6Config); err != nil {
		result = multierror.Append(result, fmt.Errorf("IPv6 cleanup failed: %w", err))
	}

	return result
}

func (ipt *IPTables) activate(handle *iptables.IPTables, config *chainConfig) error {
	// Validate chains exist or create them
	for _, chain := range config.chains {
		exists, err := handle.ChainExists(chain.table, chain.name)
		if err != nil {
			return fmt.Errorf("failed to check chain %s: %w", chain.name, err)
		}

		if !exists {
			if err := handle.NewChain(chain.table, chain.name); err != nil {
				return fmt.Errorf("failed to create chain %s: %w", chain.name, err)
			}
		}

		// Clear existing rules in chain
		if err := handle.ClearChain(chain.table, chain.name); err != nil {
			return fmt.Errorf("failed to clear chain %s: %w", chain.name, err)
		}
	}

	// Apply rules
	for _, rule := range config.rules {
		if err := handle.Append(rule.table, rule.chain, rule.args...); err != nil {
			return fmt.Errorf("failed to append rule to %s: %w", rule.chain, err)
		}
	}

	// Apply once-only rules if they don't exist
	for _, rule := range config.once {
		exists, err := handle.Exists(rule.table, rule.chain, rule.args...)
		if err != nil {
			return fmt.Errorf("failed to check rule existence: %w", err)
		}

		if !exists {
			if err := handle.Insert(rule.table, rule.chain, 1, rule.args...); err != nil {
				return fmt.Errorf("failed to insert rule to %s: %w", rule.chain, err)
			}
		}
	}

	return nil
}

func (ipt *IPTables) deactivate(handle *iptables.IPTables, config *chainConfig) error {
	var result error

	// Remove once-only rules first
	for _, rule := range config.once {
		if exists, _ := handle.Exists(rule.table, rule.chain, rule.args...); exists {
			if err := handle.Delete(rule.table, rule.chain, rule.args...); err != nil {
				result = multierror.Append(result, fmt.Errorf("failed to delete rule from %s: %w", rule.chain, err))
			}
		}
	}

	// Clean up chains
	for _, chain := range config.chains {
		if err := handle.ClearChain(chain.table, chain.name); err != nil {
			result = multierror.Append(result, fmt.Errorf("failed to clear chain %s: %w", chain.name, err))
		}
		if err := handle.DeleteChain(chain.table, chain.name); err != nil {
			result = multierror.Append(result, fmt.Errorf("failed to delete chain %s: %w", chain.name, err))
		}
	}

	return result
}

// Configuration helpers moved to separate functions for clarity
func getIPv4Config() *chainConfig {
	chains := []chain{
		{table: "mangle", name: "NETMONITOR-INGEST-OUTPUT"},
		{table: "mangle", name: "NETMONITOR-INGEST-INPUT"},
		{table: "filter", name: "NETMONITOR-FILTER"},
	}
	rules := []rule{
		{table: "mangle", chain: "NETMONITOR-INGEST-OUTPUT", args: []string{"-j", "CONNMARK", "--restore-mark"}},
		{table: "mangle", chain: "NETMONITOR-INGEST-OUTPUT", args: []string{"-m", "mark", "--mark", "0", "-j", "NFQUEUE", "--queue-num", "17040", "--queue-bypass"}},
		{table: "mangle", chain: "NETMONITOR-INGEST-INPUT", args: []string{"-j", "CONNMARK", "--restore-mark"}},
		{table: "mangle", chain: "NETMONITOR-INGEST-INPUT", args: []string{"-m", "mark", "--mark", "0", "-j", "NFQUEUE", "--queue-num", "17040", "--queue-bypass"}},
		{table: "filter", chain: "NETMONITOR-FILTER", args: []string{"-m", "mark", "--mark", "0", "-j", "DROP"}},
		{table: "filter", chain: "NETMONITOR-FILTER", args: []string{"-m", "mark", "--mark", "1700", "-j", "RETURN"}},
		{table: "filter", chain: "NETMONITOR-FILTER", args: []string{"-m", "mark", "--mark", "1701", "-p", "icmp", "-j", "RETURN"}},
		{table: "filter", chain: "NETMONITOR-FILTER", args: []string{"-m", "mark", "--mark", "1701", "-j", "REJECT", "--reject-with", "icmp-admin-prohibited"}},
		{table: "filter", chain: "NETMONITOR-FILTER", args: []string{"-m", "mark", "--mark", "1702", "-j", "DROP"}},
		{table: "filter", chain: "NETMONITOR-FILTER", args: []string{"-j", "CONNMARK", "--save-mark"}},
		{table: "filter", chain: "NETMONITOR-FILTER", args: []string{"-m", "mark", "--mark", "1710", "-j", "RETURN"}},
		{table: "filter", chain: "NETMONITOR-FILTER", args: []string{"-m", "mark", "--mark", "1711", "-p", "icmp", "-j", "RETURN"}},
		{table: "filter", chain: "NETMONITOR-FILTER", args: []string{"-m", "mark", "--mark", "1711", "-j", "REJECT", "--reject-with", "icmp-admin-prohibited"}},
		{table: "filter", chain: "NETMONITOR-FILTER", args: []string{"-m", "mark", "--mark", "1712", "-j", "DROP"}},
		{table: "filter", chain: "NETMONITOR-FILTER", args: []string{"-m", "mark", "--mark", "1717", "-j", "RETURN"}},
	}
	once := []rule{
		{table: "mangle", chain: "OUTPUT", args: []string{"-j", "NETMONITOR-INGEST-OUTPUT"}},
		{table: "mangle", chain: "INPUT", args: []string{"-j", "NETMONITOR-INGEST-INPUT"}},
		{table: "filter", chain: "OUTPUT", args: []string{"-j", "NETMONITOR-FILTER"}},
		{table: "filter", chain: "INPUT", args: []string{"-j", "NETMONITOR-FILTER"}},
	}
	return &chainConfig{chains: chains, rules: rules, once: once}
}

func getIPv6Config() *chainConfig {
	chains := []chain{
		{table: "mangle", name: "NETMONITOR-INGEST-OUTPUT"},
		{table: "mangle", name: "NETMONITOR-INGEST-INPUT"},
		{table: "filter", name: "NETMONITOR-FILTER"},
	}
	rules := []rule{
		{table: "mangle", chain: "NETMONITOR-INGEST-OUTPUT", args: []string{"-j", "CONNMARK", "--restore-mark"}},
		{table: "mangle", chain: "NETMONITOR-INGEST-OUTPUT", args: []string{"-m", "mark", "--mark", "0", "-j", "NFQUEUE", "--queue-num", "17060", "--queue-bypass"}},
		{table: "mangle", chain: "NETMONITOR-INGEST-INPUT", args: []string{"-j", "CONNMARK", "--restore-mark"}},
		{table: "mangle", chain: "NETMONITOR-INGEST-INPUT", args: []string{"-m", "mark", "--mark", "0", "-j", "NFQUEUE", "--queue-num", "17060", "--queue-bypass"}},
		{table: "filter", chain: "NETMONITOR-FILTER", args: []string{"-m", "mark", "--mark", "0", "-j", "DROP"}},
		{table: "filter", chain: "NETMONITOR-FILTER", args: []string{"-m", "mark", "--mark", "1700", "-j", "RETURN"}},
		{table: "filter", chain: "NETMONITOR-FILTER", args: []string{"-m", "mark", "--mark", "1701", "-p", "icmpv6", "-j", "RETURN"}},
		{table: "filter", chain: "NETMONITOR-FILTER", args: []string{"-m", "mark", "--mark", "1701", "-j", "REJECT", "--reject-with", "icmp6-adm-prohibited"}},
		{table: "filter", chain: "NETMONITOR-FILTER", args: []string{"-m", "mark", "--mark", "1702", "-j", "DROP"}},
		{table: "filter", chain: "NETMONITOR-FILTER", args: []string{"-j", "CONNMARK", "--save-mark"}},
		{table: "filter", chain: "NETMONITOR-FILTER", args: []string{"-m", "mark", "--mark", "1710", "-j", "RETURN"}},
		{table: "filter", chain: "NETMONITOR-FILTER", args: []string{"-m", "mark", "--mark", "1711", "-p", "icmpv6", "-j", "RETURN"}},
		{table: "filter", chain: "NETMONITOR-FILTER", args: []string{"-m", "mark", "--mark", "1711", "-j", "REJECT", "--reject-with", "icmp6-adm-prohibited"}},
		{table: "filter", chain: "NETMONITOR-FILTER", args: []string{"-m", "mark", "--mark", "1712", "-j", "DROP"}},
		{table: "filter", chain: "NETMONITOR-FILTER", args: []string{"-m", "mark", "--mark", "1717", "-j", "RETURN"}},
	}
	once := []rule{
		{table: "mangle", chain: "OUTPUT", args: []string{"-j", "NETMONITOR-INGEST-OUTPUT"}},
		{table: "mangle", chain: "INPUT", args: []string{"-j", "NETMONITOR-INGEST-INPUT"}},
		{table: "filter", chain: "OUTPUT", args: []string{"-j", "NETMONITOR-FILTER"}},
		{table: "filter", chain: "INPUT", args: []string{"-j", "NETMONITOR-FILTER"}},
	}
	return &chainConfig{chains: chains, rules: rules, once: once}
}
