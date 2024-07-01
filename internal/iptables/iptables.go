//go:build linux

package iptables

import (
	"fmt"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	"github.com/hashicorp/go-multierror"
)

var (
	v4chains = []string{
		"mangle NETMONITOR-INGEST-OUTPUT",
		"mangle NETMONITOR-INGEST-INPUT",
		"filter NETMONITOR-FILTER",
	}
	v4rules = []string{
		"mangle NETMONITOR-INGEST-OUTPUT -j CONNMARK --restore-mark",
		"mangle NETMONITOR-INGEST-OUTPUT -m mark --mark 0 -j NFQUEUE --queue-num 0 --queue-bypass",

		"mangle NETMONITOR-INGEST-INPUT -j CONNMARK --restore-mark",
		"mangle NETMONITOR-INGEST-INPUT -m mark --mark 0 -j NFQUEUE --queue-num 1 --queue-bypass",

		// Change the following rule to DROP instead of ACCEPT
		"filter NETMONITOR-FILTER -m mark --mark 0 -j DROP",
		"filter NETMONITOR-FILTER -m mark --mark 1700 -j RETURN",
		"filter NETMONITOR-FILTER -m mark --mark 1701 -p icmp -j RETURN",
		"filter NETMONITOR-FILTER -m mark --mark 1701 -j REJECT --reject-with icmp-admin-prohibited",
		"filter NETMONITOR-FILTER -m mark --mark 1702 -j DROP",
		"filter NETMONITOR-FILTER -j CONNMARK --save-mark",
		"filter NETMONITOR-FILTER -m mark --mark 1710 -j RETURN",
		"filter NETMONITOR-FILTER -m mark --mark 1711 -p icmp -j RETURN",
		"filter NETMONITOR-FILTER -m mark --mark 1711 -j REJECT --reject-with icmp-admin-prohibited",
		"filter NETMONITOR-FILTER -m mark --mark 1712 -j DROP",
		"filter NETMONITOR-FILTER -m mark --mark 1717 -j RETURN",
	}

	v4once = []string{
		"mangle OUTPUT -j NETMONITOR-INGEST-OUTPUT",
		"mangle INPUT -j NETMONITOR-INGEST-INPUT",
		"filter OUTPUT -j NETMONITOR-FILTER",
		"filter INPUT -j NETMONITOR-FILTER",
	}

	v6chains = []string{
		"mangle NETMONITOR-INGEST-OUTPUT",
		"mangle NETMONITOR-INGEST-INPUT",
		"filter NETMONITOR-FILTER",
	}
	v6rules = []string{
		"mangle NETMONITOR-INGEST-OUTPUT -j CONNMARK --restore-mark",
		"mangle NETMONITOR-INGEST-OUTPUT -m mark --mark 0 -j NFQUEUE --queue-num 0 --queue-bypass",

		"mangle NETMONITOR-INGEST-INPUT -j CONNMARK --restore-mark",
		"mangle NETMONITOR-INGEST-INPUT -m mark --mark 0 -j NFQUEUE --queue-num 1 --queue-bypass",

		// Change the following rule to DROP instead of ACCEPT
		"filter NETMONITOR-FILTER -m mark --mark 0 -j DROP",
		"filter NETMONITOR-FILTER -m mark --mark 1700 -j RETURN",
		"filter NETMONITOR-FILTER -m mark --mark 1701 -p icmpv6 -j RETURN",
		"filter NETMONITOR-FILTER -m mark --mark 1701 -j REJECT --reject-with icmp6-adm-prohibited",
		"filter NETMONITOR-FILTER -m mark --mark 1702 -j DROP",
		"filter NETMONITOR-FILTER -j CONNMARK --save-mark",
		"filter NETMONITOR-FILTER -m mark --mark 1710 -j RETURN",
		"filter NETMONITOR-FILTER -m mark --mark 1711 -p icmpv6 -j RETURN",
		"filter NETMONITOR-FILTER -m mark --mark 1711 -j REJECT --reject-with icmp6-adm-prohibited",
		"filter NETMONITOR-FILTER -m mark --mark 1712 -j DROP",
		"filter NETMONITOR-FILTER -m mark --mark 1717 -j RETURN",
	}

	v6once = []string{
		"mangle OUTPUT -j NETMONITOR-INGEST-OUTPUT",
		"mangle INPUT -j NETMONITOR-INGEST-INPUT",
		"filter OUTPUT -j NETMONITOR-FILTER",
		"filter INPUT -j NETMONITOR-FILTER",
	}
)

func activateIPTables(protocol iptables.Protocol, rules, once, chains []string) error {
	tbls, err := iptables.NewWithProtocol(protocol)
	if err != nil {
		return err
	}

	for _, chain := range chains {
		splittedRule := strings.Split(chain, " ")
		if err = tbls.ClearChain(splittedRule[0], splittedRule[1]); err != nil {
			return err
		}
	}

	for _, rule := range rules {
		splittedRule := strings.Split(rule, " ")
		if err = tbls.AppendUnique(splittedRule[0], splittedRule[1], splittedRule[2:]...); err != nil {
			return err
		}
	}

	for _, rule := range once {
		splittedRule := strings.Split(rule, " ")
		ok, err := tbls.Exists(splittedRule[0], splittedRule[1], splittedRule[2:]...)
		if err != nil {
			return err
		}
		if !ok {
			if err = tbls.Insert(splittedRule[0], splittedRule[1], 1, splittedRule[2:]...); err != nil {
				return err
			}
		}
	}

	return nil
}

func deactivateIPTables(protocol iptables.Protocol, rules, chains []string) error {
	tbls, err := iptables.NewWithProtocol(protocol)
	if err != nil {
		return err
	}

	var multierr *multierror.Error

	for _, rule := range rules {
		splittedRule := strings.Split(rule, " ")
		ok, err := tbls.Exists(splittedRule[0], splittedRule[1], splittedRule[2:]...)
		if err != nil {
			multierr = multierror.Append(multierr, err)
		}
		if ok {
			if err = tbls.Delete(splittedRule[0], splittedRule[1], splittedRule[2:]...); err != nil {
				multierr = multierror.Append(multierr, err)
			}
		}
	}

	for _, chain := range chains {
		splittedRule := strings.Split(chain, " ")
		if err = tbls.ClearChain(splittedRule[0], splittedRule[1]); err != nil {
			multierr = multierror.Append(multierr, err)
		}
		if err = tbls.DeleteChain(splittedRule[0], splittedRule[1]); err != nil {
			multierr = multierror.Append(multierr, err)
		}
	}

	return multierr.ErrorOrNil()
}

func Setup() error {
	if err := activateIPTables(iptables.ProtocolIPv4, v4rules, v4once, v4chains); err != nil {
		return err
	}

	if err := activateIPTables(iptables.ProtocolIPv6, v6rules, v6once, v6chains); err != nil {
		return err
	}

	return nil
}

func Cleanup() error {
	var result *multierror.Error

	if err := deactivateIPTables(iptables.ProtocolIPv4, v4rules, v4chains); err != nil {
		result = multierror.Append(result, err)
	}

	if err := deactivateIPTables(iptables.ProtocolIPv6, v6rules, v6chains); err != nil {
		result = multierror.Append(result, err)
	}

	if err := deactivateIPTables(iptables.ProtocolIPv4, v4once, v4chains); err != nil {
		result = multierror.Append(result, err)
	}

	if err := deactivateIPTables(iptables.ProtocolIPv6, v6once, v6chains); err != nil {
		result = multierror.Append(result, err)
	}

	return result.ErrorOrNil()
}

func GetIPTablesChains() ([]string, error) {
	chains := make([]string, 0, 100)

	for _, protocol := range []iptables.Protocol{iptables.ProtocolIPv4, iptables.ProtocolIPv6} {
		ipt, err := iptables.NewWithProtocol(protocol)
		if err != nil {
			return nil, err
		}

		for _, table := range []string{"filter", "mangle"} {
			chains = append(chains, fmt.Sprintf("%s %s", protocol, table))
			chainNames, err := ipt.ListChains(table)
			if err != nil {
				return nil, fmt.Errorf("failed to get chains of table %s: %w", table, err)
			}
			for _, name := range chainNames {
				chains = append(chains, fmt.Sprintf("  %s", name))
			}
		}
	}

	return chains, nil
}

