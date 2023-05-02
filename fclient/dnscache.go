package fclient

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

type DNSCache struct {
	resolver netResolver
	mutex    sync.Mutex
	size     int
	duration time.Duration
	entries  map[string]*dnsCacheEntry
}

func NewDNSCache(size int, duration time.Duration) *DNSCache {
	return &DNSCache{
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

type netResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

func (c *DNSCache) lookup(ctx context.Context, name string) (*dnsCacheEntry, bool) {
	// Check to see if there's something in the cache for this name.
	c.mutex.Lock()
	if entry, ok := c.entries[name]; ok {
		// Check the expiry of the cache entry. If it's still within
		// the expiry period then return the entry as-is.
		if time.Now().Before(entry.expires) {
			c.mutex.Unlock()
			return entry, true
		}

		// If it's outside of the validity then remove the entry from
		// the cache.
		delete(c.entries, name)
	}
	c.mutex.Unlock()

	// At this point there's either nothing in the cache, or there
	// was something in the cache but it's past the validity, so we
	// have nuked it. Ask the operating system to perform a lookup
	// for us.

	addrs, err := c.resolver.LookupIPAddr(ctx, name)
	if err != nil {
		return nil, false
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// If we've hit, or exceed somehow, the maximum size of the cache
	// then we will need to evict the oldest entries to make room.
	for len(c.entries) >= c.size {
		name, ts := "", time.Now().Add(c.duration)
		for n, e := range c.entries {
			if e.expires.Before(ts) {
				ts, name = e.expires, n
			}
		}
		delete(c.entries, name)
	}

	// Create a new entry, give it the validity specified when the
	// cache was created and then store it.
	entry := &dnsCacheEntry{
		addrs:   addrs,
		expires: time.Now().Add(c.duration),
	}
	c.entries[name] = entry

	// All good now - return the cache entry.
	return entry, false
}

func (c *DNSCache) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// Split up the host and port from the give address.
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("net.SplitHostPort: %w", err)
	}

	// On the first attempt, retried will be false. If we try the
	// cached entries and none of them connect, we'll retry but with
	// retried set to true. This stops us from recursing more than
	// once.
	retried := false
	dialer := net.Dialer{}

retryLookup:
	// Consult the cache for the hostname. This will cause the OS to
	// ask DNS if needed, updating the cache in the process.
	entry, cached := c.lookup(ctx, host)
	if entry == nil {
		return nil, fmt.Errorf("lookup failed for %q", host)
	}

	// Try each address in the cached entry. If we successfully connect
	// to one of those addresses then return the conn and stop there.
	for _, addr := range entry.addrs {
		conn, err := dialer.DialContext(ctx, "tcp", addr.String()+":"+port)
		if err != nil {
			continue
		}
		return conn, nil
	}

	// If we reached this point then we failed to reach any of the
	// addresses in the entry. If the entry came from the cache then
	// we'll assume that it's no good anymore - delete the cache entry
	// and then retry, which will ask the OS to consult DNS again.
	if cached && !retried {
		retried = true
		c.mutex.Lock()
		delete(c.entries, host)
		c.mutex.Unlock()
		goto retryLookup
	}

	// All attempts to find a working connection failed from either
	// cached entries or from DNS itself.
	return nil, fmt.Errorf("connection failed to %q via %d addresses", host, len(entry.addrs))
}
