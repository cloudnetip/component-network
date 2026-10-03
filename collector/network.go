package collector

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

var (
	netLoad = map[string]*NetworkStats{}
	netPrev = map[string]*NetworkStats{}
)

func (c *Collector) collectNetwork() {
	for range time.Tick(time.Second) {
		c.mu.Lock()
		c.data.Time = time.Now().UTC()
		c.mu.Unlock()
		c.netDevHandler("/proc/net/dev")
		c.netSocketHandler()
		c.netfilterConnTrackHandler()
	}
}

func deltaOrReset(cur, prev int) int {
	if cur < prev {
		return 0
	}
	return cur - prev
}

func (c *Collector) netDevHandler(file string) {
	netDev, err := os.Open(file)
	if err != nil {
		return
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(netDev)

	defer c.mu.Unlock()
	c.mu.Lock()

	// for real existing interfaces
	seen := map[string]struct{}{}

	s := bufio.NewScanner(netDev)
	for s.Scan() {
		var (
			face                                                                           string
			bytesRx, packetsRx, errsRx, dropRx, fifoRx, frameRx, compressedRx, multicastRx int
			bytesTx, packetsTx, errsTx, dropTx, fifoTx, collsTx, carrierTx, compressedTx   int
		)

		_, err := fmt.Sscanf(s.Text(),
			"%s %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d %d",
			&face, &bytesRx, &packetsRx, &errsRx, &dropRx, &fifoRx, &frameRx, &compressedRx, &multicastRx,
			&bytesTx, &packetsTx, &errsTx, &dropTx, &fifoTx, &collsTx, &carrierTx, &compressedTx)

		if err != nil {
			continue
		}

		face = strings.TrimSpace(strings.TrimSuffix(face, ":"))

		if (bytesRx == 0 && bytesTx == 0) ||
			strings.HasPrefix(face, "veth") ||
			face == "lo" {
			continue
		}

		seen[face] = struct{}{}

		if prev, ok := netPrev[face]; !ok {
			netPrev[face] = &NetworkStats{}
			netLoad[face] = &NetworkStats{}
		} else {
			netLoad[face].BytesRx = deltaOrReset(bytesRx, prev.BytesRx)
			netLoad[face].PacketsRx = deltaOrReset(packetsRx, prev.PacketsRx)
			netLoad[face].DropPksRx = deltaOrReset(dropRx, prev.DropPksRx)
			netLoad[face].ErrsPksRx = deltaOrReset(errsRx, prev.ErrsPksRx)

			netLoad[face].BytesTx = deltaOrReset(bytesTx, prev.BytesTx)
			netLoad[face].PacketsTx = deltaOrReset(packetsTx, prev.PacketsTx)
			netLoad[face].DropPksTx = deltaOrReset(dropTx, prev.DropPksTx)
			netLoad[face].ErrsPksTx = deltaOrReset(errsTx, prev.ErrsPksTx)
		}

		netPrev[face].BytesRx = bytesRx
		netPrev[face].PacketsRx = packetsRx
		netPrev[face].DropPksRx = dropRx
		netPrev[face].ErrsPksRx = errsRx

		netPrev[face].BytesTx = bytesTx
		netPrev[face].PacketsTx = packetsTx
		netPrev[face].DropPksTx = dropTx
		netPrev[face].ErrsPksTx = errsTx
	}

	for face := range netPrev {
		if _, ok := seen[face]; !ok {
			delete(netPrev, face)
			delete(netLoad, face)
		}
	}

	c.data.NetworkStats = map[string]NetworkStats{}
	for face, val := range netLoad {
		c.data.NetworkStats[face] = *val
	}
}

func (c *Collector) netSocketHandler() {
	defer c.mu.Unlock()
	c.mu.Lock()
	stats := map[string]int{}
	for name, path := range map[string]string{
		"tcp":  "/proc/net/tcp",
		"tcp6": "/proc/net/tcp6",
		"udp":  "/proc/net/udp",
		"udp6": "/proc/net/udp6",
	} {
		lines, ok := countLines(path)
		if !ok {
			continue
		}
		if lines > 0 {
			lines--
		}
		stats[name] = lines
	}
	c.data.SocketStats = stats
}

func (c *Collector) netfilterConnTrackHandler() {
	defer c.mu.Unlock()
	c.mu.Lock()
	val, err := os.ReadFile("/proc/sys/net/netfilter/nf_conntrack_count")
	if err != nil {
		return
	}
	count, err := strconv.Atoi(strings.TrimSpace(string(val)))
	if err != nil {
		log.Println("[collector] netfilterConnTrackHandler strconv err:", err)
		return
	}
	c.data.NetfilterConnTrack = count
}

func countLines(filename string) (int, bool) {
	file, err := os.Open(filename)
	if err != nil {
		log.Println("[collector] open file err:", filename)
		return 0, false
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			log.Println("[collector] close file err:", filename)
		}
	}(file)

	scanner := bufio.NewScanner(file)
	lineCount := 0
	for scanner.Scan() {
		lineCount++
	}

	if err := scanner.Err(); err != nil {
		log.Println("[collector] scan file err:", filename)
		return 0, false
	}

	return lineCount, true
}
