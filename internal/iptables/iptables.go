package iptables

import (
    "strings"

    "github.com/lonelysadness/netmonitor/internal/logger"
    "github.com/coreos/go-iptables/iptables"
    "github.com/hashicorp/go-multierror"
)

var (
    v4chains, v4rules, v4once = iptablesConfigIPv4()
    v6chains, v6rules, v6once = iptablesConfigIPv6()
)

func iptablesConfigIPv4() ([]string, []string, []string) {
    chains := []string{
        "mangle NETMONITOR-INGEST-OUTPUT",
        "mangle NETMONITOR-INGEST-INPUT",
        "filter NETMONITOR-FILTER",
    }
    rules := []string{
        "mangle NETMONITOR-INGEST-OUTPUT -j CONNMARK --restore-mark",
        "mangle NETMONITOR-INGEST-OUTPUT -m mark --mark 0 -j NFQUEUE --queue-num 17040 --queue-bypass",
        "mangle NETMONITOR-INGEST-INPUT -j CONNMARK --restore-mark",
        "mangle NETMONITOR-INGEST-INPUT -m mark --mark 0 -j NFQUEUE --queue-num 17040 --queue-bypass",
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
    once := []string{
        "mangle OUTPUT -j NETMONITOR-INGEST-OUTPUT",
        "mangle INPUT -j NETMONITOR-INGEST-INPUT",
        "filter OUTPUT -j NETMONITOR-FILTER",
        "filter INPUT -j NETMONITOR-FILTER",
    }
    return chains, rules, once
}

func iptablesConfigIPv6() ([]string, []string, []string) {
    chains := []string{
        "mangle NETMONITOR-INGEST-OUTPUT",
        "mangle NETMONITOR-INGEST-INPUT",
        "filter NETMONITOR-FILTER",
    }
    rules := []string{
        "mangle NETMONITOR-INGEST-OUTPUT -j CONNMARK --restore-mark",
        "mangle NETMONITOR-INGEST-OUTPUT -m mark --mark 0 -j NFQUEUE --queue-num 17060 --queue-bypass",
        "mangle NETMONITOR-INGEST-INPUT -j CONNMARK --restore-mark",
        "mangle NETMONITOR-INGEST-INPUT -m mark --mark 0 -j NFQUEUE --queue-num 17060 --queue-bypass",
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
    once := []string{
        "mangle OUTPUT -j NETMONITOR-INGEST-OUTPUT",
        "mangle INPUT -j NETMONITOR-INGEST-INPUT",
        "filter OUTPUT -j NETMONITOR-FILTER",
        "filter INPUT -j NETMONITOR-FILTER",
    }
    return chains, rules, once
}

func activateIPTables(protocol iptables.Protocol, chains, rules, once []string) error {
    ipt, err := iptables.NewWithProtocol(protocol)
    if err != nil {
        return err
    }

    // Clear chains before adding rules
    for _, chain := range chains {
        parts := strings.Split(chain, " ")
        if err = ipt.ClearChain(parts[0], parts[1]); err != nil {
            return err
        }
    }

    // Append rules to chains
    for _, rule := range rules {
        parts := strings.Split(rule, " ")
        if err = ipt.Append(parts[0], parts[1], parts[2:]...); err != nil {
            logger.Log.Printf("Error appending rule: %s, %v", rule, err)
            return err
        }
    }

    // Ensure once-only rules are inserted if they don't already exist
    for _, rule := range once {
        parts := strings.Split(rule, " ")
        exists, err := ipt.Exists(parts[0], parts[1], parts[2:]...)
        if err != nil {
            return err
        }
        if !exists {
            if err = ipt.Insert(parts[0], parts[1], 1, parts[2:]...); err != nil {
                logger.Log.Printf("Error inserting once-only rule: %s, %v", rule, err)
                return err
            }
        }
    }

    return nil
}

func Setup() error {
    if err := activateIPTables(iptables.ProtocolIPv4, v4chains, v4rules, v4once); err != nil {
        return err
    }
    if err := activateIPTables(iptables.ProtocolIPv6, v6chains, v6rules, v6once); err != nil {
        return err
    }
    return nil
}

func Cleanup() error {
    var result error
    if err := deactivateIPTables(iptables.ProtocolIPv4, v4chains, v4once); err != nil {
        result = multierror.Append(result, err)
    }
    if err := deactivateIPTables(iptables.ProtocolIPv6, v6chains, v6once); err != nil {
        result = multierror.Append(result, err)
    }
    return result
}

func deactivateIPTables(protocol iptables.Protocol, chains, once []string) error {
    ipt, err := iptables.NewWithProtocol(protocol)
    if err != nil {
        return err
    }

    var result *multierror.Error
    for _, rule := range once {
        parts := strings.Split(rule, " ")
        exists, err := ipt.Exists(parts[0], parts[1], parts[2:]...)
        if err != nil {
            result = multierror.Append(result, err)
        }
        if exists {
            if err = ipt.Delete(parts[0], parts[1], parts[2:]...); err != nil {
                result = multierror.Append(result, err)
            }
        }
    }

    for _, chain := range chains {
        parts := strings.Split(chain, " ")
        if err = ipt.ClearChain(parts[0], parts[1]); err != nil {
            result = multierror.Append(result, err)
        }
        if err = ipt.DeleteChain(parts[0], parts[1]); err != nil {
            result = multierror.Append(result, err)
        }
    }

    return result.ErrorOrNil()
}

