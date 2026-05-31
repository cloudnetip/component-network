package collector

import (
	"bufio"
	"context"
	"log"
	"math"
	"os/exec"
	"regexp"
	"strconv"
	"sync"
	"time"
)

var reTime = regexp.MustCompile(`time=([0-9.]+) ms`)
var PingPool = sync.Map{}

func (c *Collector) collectPing() {
	var mu sync.Mutex
	sec := time.Duration(60)
	for {
		start := time.Now()
		count := 0
		wg := &sync.WaitGroup{}
		rtt := make([]PingStats, 0)
		PingPool.Range(func(toIP, fromIP any) bool {
			count++
			wg.Add(1)
			go func(fip, tip string) {
				defer func() {
					if r := recover(); r != nil {
						log.Println("[collector] ping panic:", r)
					}
					wg.Done()
				}()
				ps, _ := ping(fip, tip, sec)
				if ps != nil {
					mu.Lock()
					rtt = append(rtt, *ps)
					mu.Unlock()
				}
			}(fromIP.(string), toIP.(string))
			return true
		})

		if count == 0 {
			time.Sleep(5 * time.Second)
			continue
		}

		wg.Wait()
		elapsed := time.Since(start)
		if elapsed < (sec/2)*time.Second { // too fast, sleep
			time.Sleep((sec / 2) * time.Second)
		}

		select {
		case c.ChanPingRTT <- rtt:
		default:
			log.Println("[collector] notice: ping chan is throttling")
		}
	}
}

func ping(fip, tip string, iteration time.Duration) (*PingStats, error) {
	ctx, cancel := context.WithTimeout(context.Background(), (iteration+2)*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	if len(fip) == 0 {
		cmd = exec.CommandContext(ctx, "ping", "-i", "1", "-c", strconv.Itoa(int(iteration+1)),
			tip)
	} else {
		cmd = exec.CommandContext(ctx, "ping", "-i", "1", "-c", strconv.Itoa(int(iteration+1)),
			"-I", fip, tip)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(stdoutPipe)
	skip := 2
	ok := 0
	rttSum := .0
	rttMin := .1e6
	rttAvg := .0
	rttMax := .0
	for scanner.Scan() {
		skip -= 1
		if skip >= 0 {
			continue
		}
		matches := reTime.FindStringSubmatch(scanner.Text())
		if len(matches) != 2 {
			continue
		}
		rtt, err := strconv.ParseFloat(matches[1], 64)
		if err != nil {
			continue
		}
		ok += 1
		rttSum += rtt
		if rtt < rttMin {
			rttMin = rtt
		}
		if rtt > rttMax {
			rttMax = rtt
		}
	}

	rttLoss := math.Round(100 - (float64(ok) / float64(iteration) * 100))
	if ok > 0 {
		rttAvg = rttSum / float64(ok)
	}
	if rttLoss >= 100 {
		rttMin = .0
	}

	if err2 := scanner.Err(); err2 != nil {
		err = err2
	}
	if err2 := cmd.Wait(); err2 != nil {
		err = err2
	}

	return &PingStats{
		From: fip,
		To:   tip,
		Min:  rttMin,
		Avg:  rttAvg,
		Max:  rttMax,
		Loss: rttLoss,
	}, err
}
