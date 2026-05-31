package collector

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"time"
)

func (c *Collector) collectWireguard() {
	time.Sleep(3 * time.Second)
	for range time.Tick(60 * time.Second) {
		out, err := exec.Command("wg", "show", "all", "dump").CombinedOutput()
		if err != nil {
			log.Println("[collector] wg dump shell err:", err, "out:", out)
			return
		}
		for _, cwp := range c.collectWireguardParser(out) {
			// wg Reject-After-Time 180 seconds + 20 sec
			if cwp.LatestHandshake+200 < time.Now().Unix() {
				continue
			}

			key := fmt.Sprintf("%d-%s", cwp.WgId, cwp.Peer)
			rx := cwp.BytesRx
			tx := cwp.BytesTx
			if pws, ok := c.prevWgStats[key]; !ok {
				rx = 0
				tx = 0
			} else {
				// when wg restarting rx/tx stats reset but prevWgStat not reset
				if rx >= pws.BytesRx {
					rx = rx - pws.BytesRx
				} else {
					rx = 0
				}
				if tx >= pws.BytesTx {
					tx = tx - pws.BytesTx
				} else {
					tx = 0
				}
			}

			c.ChanWgStats <- &WireguardStats{
				WgId:            cwp.WgId,
				Peer:            cwp.Peer,
				LatestHandshake: cwp.LatestHandshake,
				BytesRx:         rx,
				BytesTx:         tx,
			}

			c.prevWgStats[key] = cwp
		}
	}
}
func (c *Collector) collectWireguardParser(data []byte) []*WireguardStats {
	wss := make([]*WireguardStats, 0)
	s := bufio.NewScanner(bytes.NewReader(data))
	for s.Scan() {
		var (
			wgId                                    uint
			publicKey, sharedKey, endpoint, address string
			latestHS                                int64
			bytesRx, bytesTx                        uint
			keepalive                               string
		)
		// (none) - only peers
		_, err := fmt.Sscanf(s.Text(),
			"netip-wg%d %s %s %s %s %d %d %d %s",
			&wgId, &publicKey, &sharedKey, &endpoint, &address, &latestHS, &bytesRx, &bytesTx, &keepalive)
		if err != nil {
			continue
		}

		// collect from only wg servers
		if keepalive != "23" {
			continue
		}

		wss = append(wss, &WireguardStats{
			WgId:            wgId,
			Peer:            publicKey,
			LatestHandshake: latestHS,
			BytesRx:         bytesRx,
			BytesTx:         bytesTx,
		})
	}

	return wss
}
