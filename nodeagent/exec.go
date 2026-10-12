package main

// 受控执行：每条命令一个函数、字面量命令名与固定参数骨架（systemctl/ipvsadm/
// iptables/ip6tables/iptables-save/hostname），全部参数经 safeArg 校验，无 shell 无拼接。

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

func safeArg(s string) bool {
	if s == "" {
		return false
	}
	for _, ch := range s {
		switch ch {
		case ';', '|', '&', '$', '`', '(', ')', '<', '>', '\n', '\r', '\'', '"', '\\':
			return false
		}
		if ch < 32 {
			return false
		}
	}
	return true
}

func runExec(name string, args []string) (string, int, error) {
	for _, a := range args {
		if !safeArg(a) {
			return "", 0, fmt.Errorf("unsafe arg %q", a)
		}
	}
	var out, errb bytes.Buffer
	var c *exec.Cmd
	switch name {
	case "systemctl":
		c = exec.Command("systemctl", args...)
	case "ipvsadm":
		c = exec.Command("ipvsadm", args...)
	case "iptables":
		c = exec.Command("iptables", args...)
	case "ip6tables":
		c = exec.Command("ip6tables", args...)
	case "iptables-save":
		if len(args) != 0 {
			return "", 0, fmt.Errorf("iptables-save takes no args")
		}
		c = exec.Command("iptables-save")
	case "hostname":
		c = exec.Command("hostname", args...)
	default:
		return "", 0, fmt.Errorf("command not whitelisted: %s", name)
	}
	c.Stdout = &out
	c.Stderr = &errb
	err := c.Run()
	rc := 0
	if err != nil {
		rc = 1
		if ee, ok := err.(*exec.ExitError); ok {
			rc = ee.ExitCode()
		}
		return out.String(), rc, err
	}
	return out.String(), 0, nil
}

// svcActive：systemctl is-active（unit 来自模块常量/白名单动作路径）
func svcActive(unit string) string {
	if !safeArg(unit) {
		return ""
	}
	out, _, _ := runExec("systemctl", []string{"is-active", unit})
	return strings.TrimSpace(out)
}

func svcStop(unit string) error {
	_, _, err := runExec("systemctl", []string{"stop", unit})
	return err
}

func svcStart(unit string) error {
	_, _, err := runExec("systemctl", []string{"start", unit})
	return err
}

func svcDaemonReload() error {
	_, _, err := runExec("systemctl", []string{"daemon-reload"})
	return err
}

func svcRestart(unit string) (string, error) {
	out, _, err := runExec("systemctl", []string{"restart", unit})
	return out, err
}

func ipvsadmEdit(vipPort, rs string, weight int) (string, int, error) {
	return runExec("ipvsadm", []string{"-e", "-u", vipPort, "-r", rs,
		"-w", fmt.Sprintf("%d", weight), "-m"})
}

func iptablesRun(args []string) (string, int, error) {
	return runExec("iptables", args)
}

func ip6tablesRun(args []string) (string, int, error) {
	return runExec("ip6tables", args)
}

func iptablesSave() (string, error) {
	out, _, err := runExec("iptables-save", nil)
	return out, err
}

func hostnameI() string {
	out, _, err := runExec("hostname", []string{"-I"})
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}
