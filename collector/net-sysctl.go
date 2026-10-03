package collector

import (
	"maps"
	"os"
	"strings"
	"time"
)

func (c *Collector) collectSysctl() {
	c.sysCtlParams = map[string]string{
		// netfilter conntrack
		"net.netfilter.nf_conntrack_max":                     "",
		"net.netfilter.nf_conntrack_tcp_timeout_established": "",
		"net.netfilter.nf_conntrack_buckets":                 "",

		// anti-spoofing (only IPv4)
		"net.ipv4.conf.all.rp_filter":     "",
		"net.ipv4.conf.default.rp_filter": "",

		// source routing (IPv4 and IPv6)
		"net.ipv4.conf.all.accept_source_route":     "",
		"net.ipv4.conf.default.accept_source_route": "",
		"net.ipv6.conf.all.accept_source_route":     "",
		"net.ipv6.conf.default.accept_source_route": "",

		// ICP Redirects (IPv4 and IPv6)
		"net.ipv4.conf.all.accept_redirects":     "",
		"net.ipv4.conf.default.accept_redirects": "",
		"net.ipv4.conf.all.secure_redirects":     "",
		"net.ipv4.conf.default.secure_redirects": "",
		"net.ipv6.conf.all.accept_redirects":     "",
		"net.ipv6.conf.default.accept_redirects": "",

		// ICMP Redirects (only IPv4)
		"net.ipv4.conf.all.send_redirects":     "",
		"net.ipv4.conf.default.send_redirects": "",

		// ICMP protection
		"net.ipv4.icmp_echo_ignore_broadcasts":       "",
		"net.ipv4.icmp_ignore_bogus_error_responses": "",
		"net.ipv4.icmp_echo_ignore_all":              "",

		// IPv6 forwarding
		"net.ipv6.conf.all.forwarding":     "",
		"net.ipv6.conf.default.forwarding": "",

		// TCP protection and performance
		"net.ipv4.tcp_syncookies":         "",
		"net.ipv4.tcp_max_syn_backlog":    "",
		"net.ipv4.tcp_synack_retries":     "",
		"net.ipv4.tcp_max_orphans":        "",
		"net.ipv4.tcp_orphan_retries":     "",
		"net.ipv4.tcp_fin_timeout":        "",
		"net.ipv4.tcp_keepalive_time":     "",
		"net.ipv4.tcp_keepalive_intvl":    "",
		"net.ipv4.tcp_keepalive_probes":   "",
		"net.ipv4.tcp_timestamps":         "",
		"net.ipv4.tcp_sack":               "",
		"net.ipv4.tcp_congestion_control": "",
		"net.ipv4.tcp_no_metrics_save":    "",
		"net.ipv4.tcp_tw_reuse":           "",
		"net.ipv4.tcp_window_scaling":     "",
		"net.ipv4.tcp_rfc1337":            "",

		// net buffs and queues
		"net.core.netdev_max_backlog": "",
		"net.core.somaxconn":          "",
		"net.core.rmem_default":       "",
		"net.core.wmem_default":       "",
		"net.core.rmem_max":           "",
		"net.core.wmem_max":           "",
		"net.ipv4.tcp_rmem":           "",
		"net.ipv4.tcp_wmem":           "",

		// others
		"net.ipv4.ip_forward":          "",
		"net.ipv4.ip_local_port_range": "",
	}

	for range time.Tick(30 * time.Second) {
		push := false
		c.mu.Lock()
		for key := range c.sysCtlParams {
			val, err := os.ReadFile("/proc/sys/" + strings.ReplaceAll(key, ".", "/"))
			if err != nil {
				continue
			}
			newVal := strings.TrimSpace(string(val))
			if newVal == c.sysCtlParams[key] {
				continue
			}
			push = true
			c.sysCtlParams[key] = newVal
		}
		snapshot := maps.Clone(c.sysCtlParams)
		c.mu.Unlock()
		if push {
			c.ChanNetSysctl <- snapshot
		}
	}
}

func (c *Collector) collectSysctlHourly() {
	for {
		time.Sleep(time.Hour)
		c.mu.Lock()
		for key := range c.sysCtlParams {
			val, err := os.ReadFile("/proc/sys/" + strings.ReplaceAll(key, ".", "/"))
			if err != nil {
				continue
			}
			c.sysCtlParams[key] = strings.TrimSpace(string(val))
		}
		snapshot := maps.Clone(c.sysCtlParams)
		c.mu.Unlock()
		c.ChanNetSysctl <- snapshot
	}
}
