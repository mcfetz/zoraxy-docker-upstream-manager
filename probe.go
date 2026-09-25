package main

import (
	"net"
	"sync"
	"time"
)

const (
	probeTimeout     = 1500 * time.Millisecond
	probeConcurrency = 24
)

// probeTCP tests reachability of a batch of "host:port" addresses with a
// short, parallel TCP dial. The plugin runs inside the Zoraxy container, so
// the result reflects what Zoraxy itself can reach. Results are cached per
// address.
func probeTCP(addrs []string) map[string]bool {
	unique := make([]string, 0, len(addrs))
	seen := map[string]bool{}
	for _, a := range addrs {
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		unique = append(unique, a)
	}

	res := make(map[string]bool, len(unique))
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, probeConcurrency)
	)
	for _, a := range unique {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			sem <- struct{}{}
			conn, err := net.DialTimeout("tcp", addr, probeTimeout)
			if err == nil && conn != nil {
				conn.Close()
			}
			mu.Lock()
			res[addr] = err == nil
			mu.Unlock()
			<-sem
		}(a)
	}
	wg.Wait()
	return res
}
