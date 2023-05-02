package fclient

import (
	"context"
	"net"
	"testing"
	"time"
)

var dnsResolverHits chan string

func init() {
	dnsResolverHits = make(chan string, 1)
}

type dummyNetResolver struct{}

func (r *dummyNetResolver) LookupIPAddr(_ context.Context, hostname string) ([]net.IPAddr, error) {
	dnsResolverHits <- hostname
	return []net.IPAddr{
		{
			IP: net.IP("1.2.3.4"),
		},
	}, nil
}

func mustCreateCache(size int, lifetime time.Duration) *DNSCache {
	cache := NewDNSCache(size, lifetime)
	cache.resolver = &dummyNetResolver{}
	return cache
}

func TestDNSCache(t *testing.T) {
	cache := mustCreateCache(1, time.Second)
	ctx := context.Background()

	// STEP 1: First we'll start with first.com.

	// first.com shouldn't be in the cache at this point.
	if _, ok := cache.lookup(ctx, "first.com"); ok {
		t.Fatalf("shouldn't be in the cache")
	}
	select {
	case hostname := <-dnsResolverHits:
		if hostname != "first.com" {
			t.Fatalf("expected resolve for first.com, got %q", hostname)
		}
	default:
		t.Fatalf("should have hit the resolver")
	}

	// first.com should be in the cache this time.
	if _, ok := cache.lookup(ctx, "first.com"); !ok {
		t.Fatalf("should be in the cache")
	}
	select {
	case hostname := <-dnsResolverHits:
		t.Fatalf("shouldn't have hit the resolver but got a resolve for %q", hostname)
	default:
	}

	// STEP 2: Then we'll try second.net. Since the cache is only
	// one entry big, this should evict first.com.

	// second.net shouldn't be in the cache at this point.
	if _, ok := cache.lookup(ctx, "second.net"); ok {
		t.Fatalf("shouldn't be in the cache")
	}
	select {
	case hostname := <-dnsResolverHits:
		if hostname != "second.net" {
			t.Fatalf("expected resolve for second.net, got %q", hostname)
		}
	default:
		t.Fatalf("should have hit the resolver")
	}

	// second.net should be in the cache this time.
	if _, ok := cache.lookup(ctx, "second.net"); !ok {
		t.Fatalf("should be in the cache")
	}
	select {
	case hostname := <-dnsResolverHits:
		t.Fatalf("shouldn't have hit the resolver but got a resolve for %q", hostname)
	default:
	}

	// STEP 3: Now we'll retry first.com, which should have been
	// evicted.

	// first.com shouldn't be in the cache at this point.
	if _, ok := cache.lookup(ctx, "first.com"); ok {
		t.Fatalf("shouldn't be in the cache")
	}
	select {
	case hostname := <-dnsResolverHits:
		if hostname != "first.com" {
			t.Fatalf("expected resolve for first.com, got %q", hostname)
		}
	default:
		t.Fatalf("should have hit the resolver")
	}
}
