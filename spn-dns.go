package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	dnsConfFile  = "/tmp/netip-spn-dns"
	dnsHostsFile = "/tmp/netip-spn-hosts"
)

var (
	preDnsHosts   = ""
	preDnsForward = ""
)

type SpnDnsBundle struct {
	WgId    int          `json:"wgId"`
	Forward []string     `json:"forward"`
	Rules   []SpnDnsRule `json:"rules"`
}

type SpnDnsRule struct {
	IP   string `json:"ip"`
	Host string `json:"host"`
}

type SpnDns struct{}

func NewSpnDns() *SpnDns {
	return &SpnDns{}
}

func (d *SpnDns) shell(command string, errIgnore bool, timeout time.Duration) string {
	ctx, cancel := context.WithCancel(context.Background())
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()
	out, err := exec.CommandContext(ctx, "sh", "-c", command).CombinedOutput()
	if err != nil && !errIgnore {
		log.Println("[spn] dns shell err:", err, "command:", command)
	}
	return strings.TrimSpace(string(out))
}

func (d *SpnDns) up() {
	go func() {
		log.Println("[spn] dns up")
		d.shell("/coredns -conf "+dnsConfFile+" > /var/log/spn-dns.log 2>&1", false, 0)
	}()
}

func (d *SpnDns) down() {
	log.Println("[spn] dns down")
	preDnsForward = "---trim---"
	d.shell("pkill coredns", true, 10*time.Second)
	err := os.Remove(dnsConfFile)
	if err != nil && !os.IsNotExist(err) {
		log.Println("[spn] dns clean conf err:", err)
	}
}

func (d *SpnDns) Refresh(bundle *SpnDnsBundle) {
	if len(bundle.Forward) == 0 || len(bundle.Rules) == 0 {
		d.down()
		return
	}

	hosts := ""
	for _, e := range bundle.Rules {
		hosts += fmt.Sprintf("%s %s\n", e.IP, e.Host)
	}

	if preDnsHosts != hosts {
		log.Println("[spn] dns refresh hosts:", len(bundle.Rules))
		err := os.WriteFile(dnsHostsFile, []byte(hosts), 0644)
		if err != nil {
			log.Println("[spn] dns save hosts, err:", err)
			return
		}
		preDnsHosts = hosts
	}

	forward := strings.Join(bundle.Forward, " ")
	// if the dns forward have not changed
	if preDnsForward == forward {
		return
	}
	d.down()
	preDnsForward = forward

	conf := fmt.Sprintf(`.:53 {
	bind netip-wg%d
	hosts %s {
		fallthrough
	}
	forward . %s
	cache 60
	#log
	errors
}`, bundle.WgId, dnsHostsFile, forward)

	err := os.WriteFile(dnsConfFile, []byte(conf), 0644)
	if err != nil {
		log.Println("[spn] dns save conf, err:", err)
		return
	}
	d.up()
}

func (d *SpnDns) Destroy() {
	d.down()
}
