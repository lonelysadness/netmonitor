package iptables

import (
	"fmt"
	"os"
	"os/exec"
)

func runCommand(command string, args ...string) error {
	cmd := exec.Command(command, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func setupCommands(command string, commands [][]string) error {
	for _, args := range commands {
		if err := runCommand(command, args...); err != nil {
			return fmt.Errorf("failed to run %s command %v: %w", command, args, err)
		}
	}
	return nil
}

func Setup() error {
	ipv4Commands := [][]string{
		{"-F"}, {"-X"}, {"-t", "nat", "-F"}, {"-t", "nat", "-X"},
		{"-t", "mangle", "-F"}, {"-t", "mangle", "-X"},
		{"-P", "INPUT", "ACCEPT"}, {"-P", "FORWARD", "ACCEPT"}, {"-P", "OUTPUT", "ACCEPT"},
		{"-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"},
		{"-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"},
	}

	ipv6Commands := [][]string{
		{"-F"}, {"-X"}, {"-t", "nat", "-F"}, {"-t", "nat", "-X"},
		{"-t", "mangle", "-F"}, {"-t", "mangle", "-X"},
		{"-P", "INPUT", "ACCEPT"}, {"-P", "FORWARD", "ACCEPT"}, {"-P", "OUTPUT", "ACCEPT"},
		{"-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"},
		{"-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"},
	}

	if err := setupCommands("iptables", ipv4Commands); err != nil {
		return err
	}
	if err := setupCommands("ip6tables", ipv6Commands); err != nil {
		return err
	}

	return nil
}

func Cleanup() {
	ipv4Commands := [][]string{
		{"-F"}, {"-X"}, {"-t", "nat", "-F"}, {"-t", "nat", "-X"},
		{"-t", "mangle", "-F"}, {"-t", "mangle", "-X"},
	}

	ipv6Commands := [][]string{
		{"-F"}, {"-X"}, {"-t", "nat", "-F"}, {"-t", "nat", "-X"},
		{"-t", "mangle", "-F"}, {"-t", "mangle", "-X"},
	}

	if err := setupCommands("iptables", ipv4Commands); err != nil {
		fmt.Printf("failed to run iptables cleanup command %v\n", err)
	}
	if err := setupCommands("ip6tables", ipv6Commands); err != nil {
		fmt.Printf("failed to run ip6tables cleanup command %v\n", err)
	}
}

