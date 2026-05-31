package main

import (
	"encoding/json"
	"log"
	"netip-network/collector"
	"os"
	"os/signal"
	"syscall"
)

type ConnectResponse struct {
	ResponseBase
	Blackhole bool `json:"blackhole"`
}

type ConnectPayload struct {
	PayloadBase
	FirewallGroups string `json:"firewallGroups"`
}

func main() {
	go collector.Pprof()

	terminate := make(chan os.Signal, 1)
	signal.Notify(terminate, os.Interrupt, syscall.SIGTERM)
	destroy := make(chan struct{}, 1)

	conn := NewConnection(&ConnectPayload{
		PayloadBase: PayloadBase{
			Service: "network",
		},
		FirewallGroups: os.Getenv("FIREWALL_GROUPS"),
	})

	col := collector.New()

	fw := NewFirewall()
	fw.SetChanBHCounter(col.ChanBHCounter)
	if conn.Response().Blackhole {
		fw.BlackHoleEnable()
		fw.BlackHoleRestore()
	} else {
		fw.BlackHoleDestroy()
	}

	// live from nodes-handler
	go func() {
		for p := range conn.chanLive {
			var res struct {
				Command     string                 `json:"command"`
				FWRules     []FirewallRules        `json:"fwRules"`
				FWFullMode  bool                   `json:"fwFullMode"`
				IP          string                 `json:"ip"`
				Wireguards  map[int]WireguardsData `json:"wireguards"`
				WireguardId int                    `json:"wireguardId"`
				Proxies     map[int]ProxiesData    `json:"proxies"`
				ProxyId     int                    `json:"proxyId"`
				SpnDns      *SpnDnsBundle          `json:"spnDns"`
				PingIPs     map[string]string      `json:"pingIPs"`
			}
			err := json.Unmarshal(p, &res)
			if err != nil {
				log.Println("[component] decode live err:", err)
				continue
			}

			switch res.Command {
			case "services-destroy":
				destroy <- struct{}{}
				return

			case "firewall-refresh":
				fw.Refresh(res.FWRules, res.FWFullMode)
			case "firewall-disable":
				fw.Disable()
			case "blackhole-enable":
				fw.BlackHoleEnable()
			case "blackhole-disable":
				fw.BlackHoleDisable()
			case "blackhole-add":
				fw.BlackHoleExec("add", res.IP)
			case "blackhole-del":
				fw.BlackHoleExec("del", res.IP)

			case "wireguard-refresh":
				NewWireguard().Refresh(res.Wireguards)
			case "wireguard-destroy":
				NewWireguard().Destroy(res.WireguardId)
			case "wireguard-shared-refresh", "wireguard-n2n-refresh":
				NewWireguard().NodeClientRefresh(res.Wireguards)

			case "proxy-refresh":
				NewProxies().Refresh(res.Proxies)
			case "proxy-destroy":
				NewProxies().Destroy(res.ProxyId)

			case "spn-dns-refresh":
				NewSpnDns().Refresh(res.SpnDns)
			case "spn-dns-destroy":
				NewSpnDns().Destroy()

			case "ping-ips-refresh":
				log.Println("[ping] refreshing pool")
				collector.PingPool.Clear()
				for toIP, fromIP := range res.PingIPs {
					collector.PingPool.Store(toIP, fromIP)
				}
			}
		}
	}()

	log.Println("[component] ready to work")

	// writer to nodes-handler
	for {
		select {
		// chan-sender stats network
		case cn, ok := <-col.ChanNetwork:
			if !ok {
				continue
			}
			conn.chanSend <- struct {
				Event          string                    `json:"event"`
				CollectNetwork *collector.CollectNetwork `json:"collectNetwork"`
			}{
				Event:          "collect-network",
				CollectNetwork: cn,
			}

		// chan-sender stats blackhole counters
		case bhc, ok := <-col.ChanBHCounter:
			if !ok {
				continue
			}
			conn.chanSend <- struct {
				Event            string                      `json:"event"`
				BlackholeCounter *collector.BlackholeCounter `json:"blackholeCounter"`
			}{
				Event:            "blackhole-counter",
				BlackholeCounter: bhc,
			}

		// chan-sender stats wireguard
		case wgs, ok := <-col.ChanWgStats:
			if !ok {
				continue
			}
			conn.chanSend <- struct {
				Event          string                    `json:"event"`
				WireguardStats *collector.WireguardStats `json:"wireguardStats"`
			}{
				Event:          "wireguard-stats",
				WireguardStats: wgs,
			}

		// chan-sender net-sysctl
		case nsc, ok := <-col.ChanNetSysctl:
			if !ok {
				continue
			}
			conn.chanSend <- &struct {
				Event     string            `json:"event"`
				NetSysctl map[string]string `json:"netSysctl"`
			}{
				Event:     "net-sysctl",
				NetSysctl: nsc,
			}

		// chan-sender ping rtt
		case prt, ok := <-col.ChanPingRTT:
			if !ok {
				continue
			}
			conn.chanSend <- &struct {
				Event     string                `json:"event"`
				PingStats []collector.PingStats `json:"pingStats"`
			}{
				Event:     "ping-stats",
				PingStats: prt,
			}

		// handler destroy
		case <-destroy:
			fw.BlackHoleDisable()
			fw.Disable()
			NewWireguard().DestroyAll()
			log.Println("[component] service destroyed")
			log.Println("------")
			log.Println("below remains to execution manually:")
			log.Println("# docker rm -f netip.network")
			log.Println("------")
			conn.close()
			<-destroy

		// handler terminate
		case <-terminate:
			log.Println("[component] terminating...")
			conn.close()
			os.Exit(0)
		}
	}
}
