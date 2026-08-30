package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"netip-network/collector"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type FirewallRules struct {
	Protocol  string `json:"protocol"`
	Source    string `json:"source"`
	Ports     string `json:"ports"`
	Target    string `json:"target"`
	NatOutput bool   `json:"natOutput"`
}

type Firewall struct {
	table             string
	chainPre          string
	chainOut          string
	tableBlackhole    string
	mu                sync.Mutex
	blackHole         bool
	blackHoleQuantity int
	blackHoleCounter  chan<- *collector.BlackholeCounter
	blackHoleExists   map[string]struct{}
	bhStatsReg        *regexp.Regexp
	bhCancel          context.CancelFunc
}

func NewFirewall() *Firewall {
	prefix := "netip"
	if os.Getenv("FIREWALL_NFT_PREFIX") != "" {
		prefix = os.Getenv("FIREWALL_NFT_PREFIX")
	}
	return &Firewall{
		table:           prefix,
		chainPre:        prefix + "-prerouting",
		chainOut:        prefix + "-output",
		tableBlackhole:  prefix + "-blackhole",
		blackHoleExists: map[string]struct{}{},
		bhStatsReg:      regexp.MustCompile(`@(.+?) counter packets (\d+) bytes (\d+) drop`),
	}
}

func (f *Firewall) shell(command string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "sh", "-c", command).CombinedOutput()
	if err != nil {
		log.Println("[firewall] shell err:", err, "command:", command)
	}
	return strings.TrimSpace(string(out))
}

func (f *Firewall) shellOk(command string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	command += " >/dev/null 2>&1 && echo yes"
	out, err := exec.CommandContext(ctx, "sh", "-c", command).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "yes"
}

func (f *Firewall) verIp(ip string) string {
	pip := net.ParseIP(ip)
	if pip != nil && strings.Count(ip, ":") >= 2 {
		return "ip6"
	}
	return "ip"
}

func (f *Firewall) Refresh(rules []FirewallRules, fullMode bool) {
	log.Println("[firewall] refreshing rules")

	// creating nat prerouting v4/v6 if not exists
	f.shell("nft add table ip nat")
	if !f.shellOk("nft list chain ip nat PREROUTING") {
		f.shell("nft add chain ip nat PREROUTING '{ type nat hook prerouting priority dstnat; policy accept; }'")
	}
	f.shell("nft add table ip6 nat")
	if !f.shellOk("nft list chain ip6 nat PREROUTING") {
		f.shell("nft add chain ip6 nat PREROUTING '{ type nat hook prerouting priority dstnat; policy accept; }'")
	}
	// creating ip filter v4 if not exists
	f.shell("nft add table ip filter")
	if !f.shellOk("nft list chain ip filter FORWARD") {
		f.shell("nft add chain ip filter FORWARD '{ type filter hook forward priority filter; policy drop; }'")
	}

	// netip filter input ipv4/v6
	f.shell("nft add table inet " + f.table)
	f.shell("nft add chain inet " + f.table + " input '{ type filter hook input priority 0; policy accept; }'")
	if os.Getenv("FIREWALL_FLUSH_OFF") != "yes" {
		f.shell("nft flush chain inet " + f.table + " input")
	}
	if fullMode {
		f.shell("nft chain inet " + f.table + " input '{ policy drop; }'")
		f.shell("nft add rule inet " + f.table + " input iif lo accept")
		f.shell("nft add rule inet " + f.table + " input iifname docker0 accept")
		f.shell("nft add rule inet " + f.table + " input iifname cni0 accept")
	} else {
		f.shell("nft chain inet " + f.table + " input '{ policy accept; }'")
	}
	f.shell("nft add rule inet " + f.table + " input ct state invalid counter drop")
	f.shell("nft add rule inet " + f.table + " input ct state related,established accept")

	// netip filter prerouting ipv4
	f.shell("nft add chain ip nat " + f.chainPre)
	f.shell("nft flush chain ip nat " + f.chainPre)
	if fullMode {
		f.shell("nft add rule ip nat " + f.chainPre + " iifname docker0 counter return")
		f.shell("nft add rule ip nat " + f.chainPre + " iifname cni0 counter return")
	}
	existsPre := f.shellOk("nft list chain ip nat PREROUTING | grep -i 'jump " + f.chainPre + "'")
	if !existsPre {
		f.shell("nft insert rule ip nat PREROUTING fib daddr type local counter jump " + f.chainPre)
	}

	// netip filter prerouting ipv6
	f.shell("nft add chain ip6 nat " + f.chainPre)
	f.shell("nft flush chain ip6 nat " + f.chainPre)
	if fullMode {
		f.shell("nft add rule ip6 nat " + f.chainPre + " iifname docker0 counter return")
		f.shell("nft add rule ip6 nat " + f.chainPre + " iifname cni0 counter return")
	}
	existsPre6 := f.shellOk("nft list chain ip6 nat PREROUTING | grep -i 'jump " + f.chainPre + "'")
	if !existsPre6 {
		f.shell("nft insert rule ip6 nat PREROUTING fib daddr type local counter jump " + f.chainPre)
	}

	// filter rules
	for _, e := range rules {
		protocol := strings.ToLower(e.Protocol)
		target := strings.ToLower(e.Target)

		if protocol == "icmp" {
			source := ""
			if e.Source != "" {
				source = f.verIp(e.Source) + " saddr " + e.Source
			}
			f.shell("nft add rule inet " + f.table + " input " + source +
				" meta l4proto { icmp, ipv6-icmp } counter accept")
			if f.verIp(e.Source) == "ip6" {
				f.shell("nft add rule ip6 nat " + f.chainPre + " " + source +
					" meta l4proto ipv6-icmp counter return")
			} else {
				f.shell("nft add rule ip nat " + f.chainPre + " " + source +
					" meta l4proto icmp counter return")
			}
			continue
		}

		var (
			proto  = ""
			source = ""
			ports  = ""
		)

		if protocol != "" {
			proto = "meta l4proto " + protocol
		} else if e.Ports != "" {
			proto = "meta l4proto {tcp, udp}"
			protocol = "th"
		}

		if e.Source != "" {
			source = f.verIp(e.Source) + " saddr " + e.Source
		}

		if e.Ports != "" {
			ports = protocol + " dport { " + e.Ports + " }"
		}

		f.shell(fmt.Sprintf(
			"nft add rule inet %s input %s %s %s counter %s",
			f.table, proto, source, ports, target))

		// for containers ports control
		natTarget := "return"
		if target == "drop" {
			natTarget = "drop"
		}
		if e.Source != "" {
			f.shell(fmt.Sprintf(
				"nft add rule %s nat %s %s %s %s counter %s",
				f.verIp(e.Source), f.chainPre, proto, source, ports, natTarget))
		} else {
			f.shell(fmt.Sprintf(
				"nft add rule ip nat %s %s %s %s counter %s",
				f.chainPre, proto, "", ports, natTarget))
			f.shell(fmt.Sprintf(
				"nft add rule ip6 nat %s %s %s %s counter %s",
				f.chainPre, proto, "", ports, natTarget))
		}
	}

	if fullMode {
		f.shell("nft add rule ip nat " + f.chainPre + " counter drop")
		f.shell("nft add rule ip6 nat " + f.chainPre + " counter drop")
	}

	// host nat output, internal requests for spn and n2n ports
	f.shell("nft add chain ip nat " + f.chainOut)
	f.shell("nft flush chain ip nat " + f.chainOut)

	existsOut := f.shellOk("nft list chain ip nat OUTPUT | grep -i 'jump " + f.chainOut + "'")
	if !existsOut {
		f.shell("nft insert rule ip nat OUTPUT ip daddr != 127.0.0.0/8 fib daddr type local counter jump " + f.chainOut)
	}
	for _, e := range rules {
		if !e.NatOutput || e.Source == "" || e.Ports == "" {
			continue
		}
		f.shell("nft insert rule ip nat " + f.chainOut + " ip saddr " +
			e.Source + " tcp dport { " + e.Ports + " } redirect")
	}
}

func (f *Firewall) Disable() {
	if !f.shellOk("nft list table inet " + f.table) {
		return
	}
	log.Println("[firewall] disabling")

	f.shell("nft delete table inet " + f.table)

	// rm nat prerouting ipv4
	rmPre := f.shell("nft -a list chain ip nat PREROUTING 2> /dev/null | grep -i 'jump " + f.chainPre + "' | head -n 1")
	if rmPre != "" {
		spl := strings.Split(rmPre, " # handle ")
		if len(spl) > 1 {
			f.shell("nft delete rule ip nat PREROUTING handle " + spl[1])
		}
	}
	f.shell("nft flush chain ip nat " + f.chainPre + " 2> /dev/null || true")
	if f.shellOk("nft list chain ip nat " + f.chainPre) {
		f.shell("nft delete chain ip nat " + f.chainPre)
	}

	// rm nat prerouting ipv6
	rmPre6 := f.shell("nft -a list chain ip6 nat PREROUTING 2> /dev/null | grep -i 'jump " + f.chainPre + "' | head -n 1")
	if rmPre6 != "" {
		spl := strings.Split(rmPre6, " # handle ")
		if len(spl) > 1 {
			f.shell("nft delete rule ip6 nat PREROUTING handle " + spl[1])
		}
	}
	f.shell("nft flush chain ip6 nat " + f.chainPre + " 2> /dev/null || true")
	if f.shellOk("nft list chain ip6 nat " + f.chainPre) {
		f.shell("nft delete chain ip6 nat " + f.chainPre)
	}
}

func (f *Firewall) SetChanBHCounter(counter chan<- *collector.BlackholeCounter) {
	f.mu.Lock()
	f.blackHoleCounter = counter
	f.mu.Unlock()
}

func (f *Firewall) BlackHoleEnable() {
	f.mu.Lock()
	if f.blackHole {
		f.mu.Unlock()
		return
	}
	f.blackHole = true
	ctx, cancel := context.WithCancel(context.Background())
	f.bhCancel = cancel
	f.mu.Unlock()

	exists := f.shellOk("nft list table inet " + f.tableBlackhole)
	if !exists {
		log.Println("[blackhole] initialing")

		init := []string{
			"nft add table inet " + f.tableBlackhole,
			"nft add chain inet " + f.tableBlackhole +
				" input '{ type filter hook input priority -200; policy accept ; }'",
			"nft add chain inet " + f.tableBlackhole +
				" forward '{ type filter hook forward priority -200; policy accept ; }'",
			"nft add set inet " + f.tableBlackhole + " IPv4 '{ type ipv4_addr; flags interval; }'",
			"nft add set inet " + f.tableBlackhole + " IPv6 '{ type ipv6_addr; flags interval; }'",
			"nft add rule inet " + f.tableBlackhole + " input ip saddr @IPv4 counter drop",
			"nft add rule inet " + f.tableBlackhole + " input ip6 saddr @IPv6 counter drop",
			"nft add rule inet " + f.tableBlackhole + " forward ip saddr @IPv4 counter drop",
			"nft add rule inet " + f.tableBlackhole + " forward ip6 saddr @IPv6 counter drop",
		}
		for _, i := range init {
			f.shell(i)
		}
	}

	go f.bhStatsCollect(ctx)
}

func (f *Firewall) BlackHoleExec(act, ip string) {
	f.mu.Lock()
	enabled := f.blackHole
	f.mu.Unlock()
	if !enabled {
		return
	}

	set := "IPv4"
	if f.verIp(ip) == "ip6" {
		set = "IPv6"
	}
	if act != "add" {
		act = "delete"
	}
	ok := f.shellOk(fmt.Sprintf("nft %s element inet %s %s '{ %s }'", act, f.tableBlackhole, set, ip))
	if !ok {
		return
	}

	key := f.normKey(ip)

	f.mu.Lock()
	if act == "add" {
		if _, ok := f.blackHoleExists[key]; !ok {
			f.blackHoleExists[key] = struct{}{}
			f.blackHoleQuantity++
		}
	}
	if act == "delete" {
		if _, ok := f.blackHoleExists[key]; ok {
			delete(f.blackHoleExists, key)
			f.blackHoleQuantity--
		}
	}
	f.mu.Unlock()
}

func (f *Firewall) BlackHoleRestore() {
	log.Println("[blackhole] restoring db from nft")

	for _, v := range []int{4, 6} {
		set := f.shell(fmt.Sprintf("nft -j list set inet %s IPv%d", f.tableBlackhole, v))

		var nft struct {
			NFTables []struct {
				Set struct {
					Elem []interface{} `json:"elem"`
				} `json:"set"`
			} `json:"nftables"`
		}

		err := json.Unmarshal([]byte(set), &nft)
		if err != nil {
			continue
		}

		f.mu.Lock()
		for _, n := range nft.NFTables {
			if len(n.Set.Elem) == 0 {
				continue
			}
			for _, i := range n.Set.Elem {
				if ip, ok := i.(string); ok {
					key := f.normKey(ip)
					if _, exists := f.blackHoleExists[key]; !exists {
						f.blackHoleExists[key] = struct{}{}
						f.blackHoleQuantity++
					}
				} else if rn, ok := i.(map[string]any); ok {
					if ip, ok := rn["prefix"].(map[string]any); ok {
						key := fmt.Sprintf("%s/%0.f", ip["addr"], ip["len"])
						if _, exists := f.blackHoleExists[key]; !exists {
							f.blackHoleExists[key] = struct{}{}
							f.blackHoleQuantity++
						}
					}
				}
			}
		}
		f.mu.Unlock()
	}
}

func (f *Firewall) BlackHoleDisable() {
	f.mu.Lock()
	if !f.blackHole {
		f.mu.Unlock()
		return
	}
	f.blackHole = false
	f.mu.Unlock()

	f.BlackHoleDestroy()
}

func (f *Firewall) BlackHoleDestroy() {
	f.mu.Lock()
	if f.bhCancel != nil {
		f.bhCancel()
		f.bhCancel = nil
	}
	f.blackHoleQuantity = 0
	f.blackHoleExists = map[string]struct{}{}
	f.mu.Unlock()

	exists := f.shellOk("nft list table inet " + f.tableBlackhole)
	if exists {
		log.Println("[blackhole] destroying")
		f.shell("nft delete table inet " + f.tableBlackhole)
	}
}

func (f *Firewall) bhStatsCollect(ctx context.Context) {
	ticker := time.NewTicker(time.Second / 100)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			ticker.Reset(30 * time.Second)

			ifl := f.shell("nft list chain inet "+f.tableBlackhole+" input") +
				f.shell("nft list chain inet "+f.tableBlackhole+" forward")

			f.mu.Lock()
			quantity := f.blackHoleQuantity
			counterChan := f.blackHoleCounter
			f.mu.Unlock()

			bhc := &collector.BlackholeCounter{
				QuantityRules: quantity,
			}
			for _, m := range f.bhStatsReg.FindAllStringSubmatch(ifl, -1) {
				if len(m) < 3 {
					continue
				}
				packets, err := strconv.Atoi(m[2])
				if err != nil {
					packets = 0
				}
				bytes, err := strconv.Atoi(m[3])
				if err != nil {
					bytes = 0
				}
				if m[1] == "IPv4" {
					bhc.IPv4.Packets += packets
					bhc.IPv4.Bytes += bytes
				}
				if m[1] == "IPv6" {
					bhc.IPv6.Packets += packets
					bhc.IPv6.Bytes += bytes
				}
			}

			if counterChan != nil {
				counterChan <- bhc
			}
		case <-ctx.Done():
			return
		}
	}
}

func (f *Firewall) normKey(cidr string) string {
	if strings.Contains(cidr, "/") {
		return cidr
	}
	if f.verIp(cidr) == "ip6" {
		return cidr + "/128"
	}
	return cidr + "/32"
}
