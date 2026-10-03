package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type WireguardsData struct {
	PrivateKey string          `json:"privateKey"`
	Masquerade bool            `json:"masquerade"`
	Shared     bool            `json:"shared"`
	Address    string          `json:"address"`
	Network    string          `json:"network"`
	Port       int             `json:"port"`
	MTU        int             `json:"mtu"`
	Peers      []WireguardPeer `json:"peers"`
}

type WireguardPeer struct {
	PublicKey  string `json:"publicKey"`
	SharedKey  string `json:"sharedKey"`
	Address    string `json:"address"`
	Endpoint   string `json:"endpoint"`
	AllowedIPs string `json:"allowedIPs"`
}

var reWgInf = regexp.MustCompile(`^netip-wg([0-9]+)$`)

type Wireguard struct{}

func NewWireguard() *Wireguard {
	return &Wireguard{}
}

func (w *Wireguard) shell(command string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "sh", "-c", command).CombinedOutput()
	if err != nil {
		log.Println("[wg] shell err:", err, "command:", command)
	}
	return strings.TrimSpace(string(out))
}

func (w *Wireguard) shellOk(command string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	command += " >/dev/null 2>&1 && echo yes"
	out, err := exec.CommandContext(ctx, "sh", "-c", command).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "yes"
}

func (w *Wireguard) fileConf(wgId int) string {
	return fmt.Sprintf("/tmp/netip-wg%d.conf", wgId)
}

func (w *Wireguard) up(wgId int, masquerade, shared bool, network string) {
	w.shell("wg-quick up " + w.fileConf(wgId))

	if masquerade {
		inf := fmt.Sprintf("netip-wg%d", wgId)
		w.shell("nft add table inet " + inf)
		w.shell("nft add chain inet " + inf + " forward-wg '{ type filter hook forward priority -100; policy accept ; }'")
		w.shell("nft add rule inet " + inf + " forward-wg iifname " + inf + " counter mark set 0x10f01")
		w.shell("nft add rule inet " + inf + " forward-wg oifname " + inf + " counter mark set 0x10f01")
		w.shell("nft add chain inet " + inf + " masquerade-wg '{ type nat hook postrouting priority srcnat; policy accept; }'")

		// block access to private addresses for usual wireguard server
		if !shared {
			w.shell("nft add rule inet " + inf + " masquerade-wg ip saddr " + network +
				" ip daddr != '{ 10.0.0.0/8, 100.64.0.0/10, 172.16.0.0/12, 192.168.0.0/16 }' counter masquerade")
			w.shell("nft add rule inet  " + inf + " masquerade-wg ip saddr " + network +
				" ip daddr '{ 10.0.0.0/8, 100.64.0.0/10, 172.16.0.0/12, 192.168.0.0/16 }' counter drop")
		}

		w.shell("nft list chain ip filter FORWARD | grep 0x00010f01 >/dev/null 2>&1 ||" +
			" nft add rule ip filter FORWARD mark 0x10f01 accept")
	}
}

// sharedMasquerade flush masquerade-wg and adding access rules
func (w *Wireguard) sharedMasquerade(wgId int, access map[string][]string) {
	inf := fmt.Sprintf("netip-wg%d", wgId)
	w.shell("nft flush chain inet " + inf + " masquerade-wg")

	for address, allowed := range access {
		if len(allowed) == 0 {
			continue
		}
		w.shell("nft add rule inet " + inf + " masquerade-wg ip saddr " + address +
			" ip daddr '{ " + strings.Join(allowed, ", ") + " }' counter masquerade")
	}
}

func (w *Wireguard) down(wgId int) {
	w.shell("wg-quick down " + w.fileConf(wgId))

	table := fmt.Sprintf("netip-wg%d", wgId)
	if w.shellOk("nft list table inet " + table) {
		w.shell("nft delete table inet " + table)
	}
}

func (w *Wireguard) exists(wgId int) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	_, err := exec.CommandContext(ctx, "sh", "-c",
		fmt.Sprintf("wg show netip-wg%d", wgId)).CombinedOutput()
	return err == nil
}

func (w *Wireguard) reload(wgId int) {
	// "wg syncconf netip-wg123 <(wg-quick strip /tmp/netip.conf)" - wg-quick leaves left zombie process
	w.shell(fmt.Sprintf("wg-quick strip %s > /tmp/netip-wg%d-reload.conf && "+
		"wg syncconf netip-wg%d /tmp/netip-wg%d-reload.conf && "+
		"rm /tmp/netip-wg%d-reload.conf",
		w.fileConf(wgId), wgId, wgId, wgId, wgId))
}

func (w *Wireguard) Refresh(wgs map[int]WireguardsData) {
	wgIds := make([]string, 0, len(wgs))
	for wgId, e := range wgs {
		wgIds = append(wgIds, fmt.Sprint(wgId))

		conf := strings.Builder{}
		conf.WriteString(fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
ListenPort = %d
SaveConfig = false
MTU = %d
`, e.PrivateKey, e.Network, e.Port, e.MTU))
		peers := map[string][]string{}
		for _, p := range e.Peers {
			if len(p.PublicKey) == 0 {
				continue
			}
			peers[p.Address] = strings.Split(p.AllowedIPs, ", ")

			conf.WriteString("\n[Peer]\nPublicKey = " + p.PublicKey)
			if p.SharedKey != "" {
				conf.WriteString("\nPresharedKey = " + p.SharedKey)
			}
			if p.AllowedIPs != "" {
				conf.WriteString("\nAllowedIPs = " + p.Address + "/32, " + p.AllowedIPs)
			} else {
				conf.WriteString("\nAllowedIPs = " + p.Address + "/32")
			}
			conf.WriteString("\nPersistentKeepalive = 23\n")
		}

		err := os.WriteFile(w.fileConf(wgId), []byte(conf.String()), 0600)
		if err != nil {
			log.Println("[wg] err save conf, wg id:", wgId)
			continue
		}

		if len(peers) > 0 {
			if w.exists(wgId) {
				w.reload(wgId)
			} else {
				w.up(wgId, e.Masquerade, e.Shared, e.Network)
			}
			if e.Shared {
				w.sharedMasquerade(wgId, peers)
			}
		} else if w.exists(wgId) {
			w.down(wgId)
		}
	}

	if len(wgIds) > 0 {
		log.Println("[wg] refresh, ids:", strings.Join(wgIds, ", "))
	}
}

func (w *Wireguard) Destroy(wgId int) {
	log.Println("[wg] destroy, id:", wgId)
	if w.exists(wgId) {
		w.down(wgId)
	}
}

func (w *Wireguard) DestroyAll() {
	out := w.shell("wg show interfaces")
	for _, ifa := range strings.Fields(out) {
		m := reWgInf.FindStringSubmatch(ifa)
		if m == nil {
			continue
		}
		id, _ := strconv.Atoi(m[1])
		w.Destroy(id)
	}
}

func (w *Wireguard) NodeClientRefresh(wgs map[int]WireguardsData) {
	wgIds := make([]string, 0, len(wgs))
	for wgId, e := range wgs {
		wgIds = append(wgIds, fmt.Sprint(wgId))

		conf := strings.Builder{}
		conf.WriteString(fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32
SaveConfig = false
MTU = %d
`, e.PrivateKey, e.Address, e.MTU))

		quantityPeers := 0
		for _, p := range e.Peers {
			if len(p.PublicKey) == 0 {
				continue
			}
			quantityPeers++
			conf.WriteString(fmt.Sprintf(`
[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = %s
Endpoint = %s
PersistentKeepalive = 25
`, p.PublicKey, p.SharedKey, p.AllowedIPs, p.Endpoint))
		}
		err := os.WriteFile(w.fileConf(wgId), []byte(conf.String()), 0600)
		if err != nil {
			log.Println("[wg] err save client conf, wg id:", wgId)
			continue
		}

		if quantityPeers > 0 {
			if w.exists(wgId) {
				w.reload(wgId)
			} else {
				w.up(wgId, e.Masquerade, false, e.Network)
			}
		} else if w.exists(wgId) {
			w.down(wgId)
		}
	}

	if len(wgIds) > 0 {
		log.Println("[wg] refresh client, ids:", strings.Join(wgIds, ", "))
	}
}
