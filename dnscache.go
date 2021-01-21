package gomatrixserverlib

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

type dnsCache struct {
	resolver *net.Resolver
	mutex    sync.Mutex
	size     int
	duration time.Duration
	entries  map[string]*dnsCacheEntry
}

func newDNSCache(size int, duration time.Duration) *dnsCache {
	return &dnsCache{
		resolver: net.DefaultResolver,
		size:     size,
		duration: duration,
		entries:  make(map[string]*dnsCacheEntry),
	}
}

type dnsCacheEntry struct {
	addrs   []net.IPAddr
	expires time.Time
}

func (c *dnsCache) lookup(ctx context.Context, name string) (*dnsCacheEntry, bool) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if entry, ok := c.entries[name]; ok {
		if time.Now().Before(entry.expires) {
			return entry, true
		}
	}

	addrs, err := c.resolver.LookupIPAddr(ctx, name)
	if err != nil {
		return nil, false
	}

	for len(c.entries) >= c.size {
		ts := time.Now().Add(c.duration)
		name := ""
		for n, e := range c.entries {
			if e.expires.Before(ts) {
				ts, name = e.expires, n
			}
		}
		delete(c.entries, name)
	}

	entry := &dnsCacheEntry{
		addrs:   addrs,
		expires: time.Now().Add(c.duration),
	}
	c.entries[name] = entry

	return entry, false
}

func (c *dnsCache) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("net.SplitHostPort: %w", err)
	}

	retried := false
	dialer := net.Dialer{}

retryLookup:
	entry, _ := c.lookup(ctx, host)
	if entry == nil {
		return nil, fmt.Errorf("lookup failed for %q", host)
	}

	for _, addr := range entry.addrs {
		conn, err := dialer.DialContext(ctx, "tcp", addr.String()+":"+port)
		if err != nil {
			continue
		}
		return conn, nil
	}

	if !retried {
		retried = true
		c.mutex.Lock()
		delete(c.entries, host)
		c.mutex.Unlock()
		goto retryLookup
	}

	return nil, fmt.Errorf("connection failed to %q via %d addresses", host, len(entry.addrs))
}
