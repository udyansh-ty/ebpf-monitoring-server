// Package programs provides eBPF program management and integration utilities.
package programs

import (
	"context"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/srodi/ebpf-server/pkg/logger"
)

// ANCHOR: Interface Index Resolver - Phase 1B - Feb 6, 2026
// WHY: Map kernel ifindex to human-readable interface names
// WHAT: Query /sys/class/net/ to build and maintain ifindex → name mapping
// HOW: Scan sysfs, cache results, handle interface hotplug with periodic refresh

// InterfaceResolver resolves kernel interface indices to human-readable names.
// It maintains a cache of ifindex → interface_name mappings by scanning
// /sys/class/net/ directory. The cache is periodically refreshed to detect
// interface hotplug events (new/removed interfaces, renames).
type InterfaceResolver struct {
	cache   map[int]string        // ifindex → interface_name mapping
	mu      sync.RWMutex          // Protects cache map
	log     *logger.Logger         // Logger instance
	sysPath string                 // Path to /sys/class/net (configurable for testing)
	quit    chan struct{}          // Signal to stop refresh goroutine
	wg      sync.WaitGroup         // Wait for goroutine completion
	stats   *ResolverStats         // Statistics tracking
}

// ResolverStats tracks resolver performance metrics
type ResolverStats struct {
	CacheHits         int64
	CacheMisses       int64
	RefreshCount      int64
	InterfacesFound   int
	LastRefreshTime   time.Time
	LastRefreshError  string
	mu                sync.RWMutex
}

// NewInterfaceResolver creates a new interface resolver.
// It initially scans /sys/class/net/ to populate the cache.
// ANCHOR: Logger Pointer Alignment - Build fix - Feb 25, 2026
// Accept *logger.Logger to match GetDefaultLogger return type.
func NewInterfaceResolver(log *logger.Logger) *InterfaceResolver {
	resolver := &InterfaceResolver{
		cache:   make(map[int]string),
		log:     log,
		sysPath: "/sys/class/net",
		quit:    make(chan struct{}),
		stats: &ResolverStats{
			LastRefreshTime: time.Now(),
		},
	}

	// Initial cache population
	if err := resolver.refreshCacheInternal(); err != nil {
		// ANCHOR: Logger Method Fix - Build fix - Feb 25, 2026
		// Use package-level logger since Logger type lacks Warnf.
		logger.Warnf("Failed to initialize interface resolver cache: %v", err)
	}

	return resolver
}

// Start begins the periodic cache refresh goroutine.
// Must be called after creating the resolver.
// The resolver will refresh the cache every 10 seconds to detect hotplug events.
func (r *InterfaceResolver) Start(ctx context.Context) {
	r.wg.Add(1)
	go r.refreshLoop(ctx)
}

// Stop gracefully stops the refresh goroutine.
// Should be called when shutting down the aggregator.
func (r *InterfaceResolver) Stop() {
	close(r.quit)
	r.wg.Wait()
}

// GetInterfaceName resolves an interface index to its name.
// Returns the interface name (e.g., "eth0", "eth1", "wlan0").
// On error or if the interface is not found, returns empty string and error.
//
// This method is optimized for speed:
// - Cache hit (fast path): O(1) map lookup (~50ns)
// - Cache miss (slow path): O(n) directory scan + cache update (~10ms)
func (r *InterfaceResolver) GetInterfaceName(ctx context.Context, ifindex int) (string, error) {
	// Validate input
	if ifindex <= 0 {
		return "", fmt.Errorf("invalid interface index: %d", ifindex)
	}

	// Fast path: check cache with read lock
	r.mu.RLock()
	name, found := r.cache[ifindex]
	r.mu.RUnlock()

	if found {
		r.recordCacheHit()
		return name, nil
	}

	r.recordCacheMiss()

	// Slow path: scan /sys/class/net/ to find the interface
	ifaces, err := ioutil.ReadDir(r.sysPath)
	if err != nil {
		return "", fmt.Errorf("failed to read %s: %w", r.sysPath, err)
	}

	for _, iface := range ifaces {
		if !iface.IsDir() {
			continue
		}

		ifName := iface.Name()
		idx, err := r.readIfindex(ifName)
		if err != nil {
			if r.log != nil {
				r.log.Debugf("Failed to read ifindex for %s: %v", ifName, err)
			}
			continue
		}

		// Update cache
		r.mu.Lock()
		r.cache[idx] = ifName
		r.mu.Unlock()

		// Check if this is the interface we're looking for
		if idx == ifindex {
			return ifName, nil
		}
	}

	// Interface not found
	return "", fmt.Errorf("interface with index %d not found", ifindex)
}

// GetAllInterfaces returns a copy of the complete ifindex → name mapping.
// Used for debugging and statistics.
func (r *InterfaceResolver) GetAllInterfaces(ctx context.Context) map[int]string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Return a copy to prevent external modifications
	result := make(map[int]string)
	for k, v := range r.cache {
		result[k] = v
	}
	return result
}

// RefreshCache forces a cache refresh and detects interface hotplug events.
// This scans /sys/class/net/ and updates the cache with any new interfaces
// or removals.
func (r *InterfaceResolver) RefreshCache(ctx context.Context) error {
	return r.refreshCacheInternal()
}

// GetStats returns current resolver statistics.
func (r *InterfaceResolver) GetStats() ResolverStats {
	r.stats.mu.RLock()
	defer r.stats.mu.RUnlock()
	return *r.stats
}

// Private methods

// refreshLoop runs in a background goroutine and periodically refreshes the cache.
// This detects interface hotplug events (new interfaces, removals, renames).
func (r *InterfaceResolver) refreshLoop(ctx context.Context) {
	defer r.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := r.refreshCacheInternal(); err != nil {
				if r.log != nil {
					r.log.Debugf("Cache refresh error: %v", err)
				}
				r.stats.mu.Lock()
				r.stats.LastRefreshError = err.Error()
				r.stats.mu.Unlock()
			}

		case <-r.quit:
			return

		case <-ctx.Done():
			return
		}
	}
}

// refreshCacheInternal scans /sys/class/net/ and updates the cache.
// This is the core refresh logic used by both initial population and periodic refresh.
func (r *InterfaceResolver) refreshCacheInternal() error {
	ifaces, err := ioutil.ReadDir(r.sysPath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", r.sysPath, err)
	}

	// Build new cache
	newCache := make(map[int]string)

	for _, iface := range ifaces {
		if !iface.IsDir() {
			continue
		}

		ifName := iface.Name()

		// Skip special interfaces
		if ifName == "lo" || ifName == "." || ifName == ".." {
			continue
		}

		idx, err := r.readIfindex(ifName)
		if err != nil {
			if r.log != nil {
				r.log.Debugf("Failed to read ifindex for %s: %v", ifName, err)
			}
			continue
		}

		newCache[idx] = ifName
	}

	// Update stats
	r.stats.mu.Lock()
	r.stats.RefreshCount++
	r.stats.InterfacesFound = len(newCache)
	r.stats.LastRefreshTime = time.Now()
	r.stats.LastRefreshError = ""
	r.stats.mu.Unlock()

	// Atomically replace cache
	r.mu.Lock()
	r.cache = newCache
	r.mu.Unlock()

	return nil
}

// readIfindex reads the interface index from /sys/class/net/<ifname>/if_index
func (r *InterfaceResolver) readIfindex(ifName string) (int, error) {
	ifindexPath := filepath.Join(r.sysPath, ifName, "if_index")

	data, err := ioutil.ReadFile(ifindexPath)
	if err != nil {
		return 0, err
	}

	// Parse the integer value
	ifindex, err := strconv.Atoi(string(data[:len(data)-1])) // -1 to remove newline
	if err != nil {
		return 0, fmt.Errorf("failed to parse ifindex: %w", err)
	}

	return ifindex, nil
}

// recordCacheHit increments cache hit counter
func (r *InterfaceResolver) recordCacheHit() {
	r.stats.mu.Lock()
	r.stats.CacheHits++
	r.stats.mu.Unlock()
}

// recordCacheMiss increments cache miss counter
func (r *InterfaceResolver) recordCacheMiss() {
	r.stats.mu.Lock()
	r.stats.CacheMisses++
	r.stats.mu.Unlock()
}

// TestingSetSysPath sets the sysfs path for testing purposes.
// This should only be used in tests to mock /sys/class/net/
func (r *InterfaceResolver) TestingSetSysPath(path string) {
	r.sysPath = path
}
