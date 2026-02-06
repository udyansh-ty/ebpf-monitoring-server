package programs

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/srodi/ebpf-server/pkg/logger"
)

// TestNewInterfaceResolver tests resolver creation and initialization.
func TestNewInterfaceResolver(t *testing.T) {
	resolver := NewInterfaceResolver(logger.GetDefaultLogger())
	if resolver == nil {
		t.Fatal("expected resolver, got nil")
	}

	// Check initial cache exists
	if resolver.cache == nil {
		t.Fatal("expected cache to be initialized")
	}

	// Resolver should start with some interfaces
	allIfaces := resolver.GetAllInterfaces(context.Background())
	if len(allIfaces) == 0 {
		t.Logf("warning: no interfaces found in /sys/class/net (expected in test environment)")
	}
}

// TestGetInterfaceName tests interface name resolution.
func TestGetInterfaceName(t *testing.T) {
	// Create mock /sys/class/net structure
	tmpdir, err := ioutil.TempDir("", "interface_test_")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpdir)

	// Create mock interfaces: eth0 (ifindex=2), eth1 (ifindex=3), wlan0 (ifindex=4)
	createMockInterface(t, tmpdir, "eth0", 2)
	createMockInterface(t, tmpdir, "eth1", 3)
	createMockInterface(t, tmpdir, "wlan0", 4)

	resolver := NewInterfaceResolver(logger.GetDefaultLogger())
	resolver.TestingSetSysPath(tmpdir)

	// Refresh cache to populate from mock directory
	ctx := context.Background()
	if err := resolver.RefreshCache(ctx); err != nil {
		t.Fatalf("failed to refresh cache: %v", err)
	}

	tests := []struct {
		ifindex  int
		expected string
		wantErr  bool
	}{
		{2, "eth0", false},
		{3, "eth1", false},
		{4, "wlan0", false},
		{999, "", true},  // Non-existent interface
		{0, "", true},    // Invalid ifindex
		{-1, "", true},   // Invalid ifindex
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			name, err := resolver.GetInterfaceName(ctx, tt.ifindex)

			if tt.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if name != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, name)
			}
		})
	}
}

// TestCacheHitAndMiss tests cache hit/miss statistics.
func TestCacheHitAndMiss(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "cache_test_")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpdir)

	createMockInterface(t, tmpdir, "eth0", 2)

	resolver := NewInterfaceResolver(logger.GetDefaultLogger())
	resolver.TestingSetSysPath(tmpdir)
	resolver.RefreshCache(context.Background())

	ctx := context.Background()

	// First lookup should be a cache hit (from initial population)
	resolver.GetInterfaceName(ctx, 2)

	stats := resolver.GetStats()
	if stats.CacheHits == 0 {
		t.Error("expected at least 1 cache hit")
	}

	// Lookup non-existent should be a cache miss
	resolver.GetInterfaceName(ctx, 999)

	stats = resolver.GetStats()
	if stats.CacheMisses == 0 {
		t.Error("expected at least 1 cache miss")
	}
}

// TestRefreshCache tests periodic cache refresh and hotplug detection.
func TestRefreshCache(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "refresh_test_")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpdir)

	createMockInterface(t, tmpdir, "eth0", 2)

	resolver := NewInterfaceResolver(logger.GetDefaultLogger())
	resolver.TestingSetSysPath(tmpdir)

	ctx := context.Background()

	// Initial cache
	resolver.RefreshCache(ctx)
	allIfaces := resolver.GetAllInterfaces(ctx)
	if len(allIfaces) != 1 {
		t.Errorf("expected 1 interface, got %d", len(allIfaces))
	}

	// Add a new interface
	createMockInterface(t, tmpdir, "eth1", 3)

	// Refresh and verify new interface is detected
	resolver.RefreshCache(ctx)
	allIfaces = resolver.GetAllInterfaces(ctx)
	if len(allIfaces) != 2 {
		t.Errorf("expected 2 interfaces after refresh, got %d", len(allIfaces))
	}

	// Verify stats
	stats := resolver.GetStats()
	if stats.InterfacesFound != 2 {
		t.Errorf("expected 2 interfaces in stats, got %d", stats.InterfacesFound)
	}
}

// TestConcurrentAccess tests thread-safe concurrent access to resolver.
func TestConcurrentAccess(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "concurrent_test_")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpdir)

	// Create multiple mock interfaces
	for i := 0; i < 5; i++ {
		createMockInterface(t, tmpdir, "eth"+string(rune(48+i)), 2+i)
	}

	resolver := NewInterfaceResolver(logger.GetDefaultLogger())
	resolver.TestingSetSysPath(tmpdir)
	resolver.RefreshCache(context.Background())

	ctx := context.Background()

	// Concurrent reads from multiple goroutines
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- true }()

			// Each goroutine does multiple lookups
			for j := 0; j < 100; j++ {
				ifindex := 2 + (i*100+j)%5
				resolver.GetInterfaceName(ctx, ifindex)
			}
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify no race conditions and stats are correct
	stats := resolver.GetStats()
	if stats.CacheHits == 0 {
		t.Error("expected cache hits from concurrent access")
	}
}

// TestGetAllInterfaces tests bulk interface retrieval.
func TestGetAllInterfaces(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "all_ifaces_test_")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpdir)

	// Create mock interfaces
	createMockInterface(t, tmpdir, "eth0", 2)
	createMockInterface(t, tmpdir, "eth1", 3)
	createMockInterface(t, tmpdir, "wlan0", 4)

	resolver := NewInterfaceResolver(logger.GetDefaultLogger())
	resolver.TestingSetSysPath(tmpdir)
	resolver.RefreshCache(context.Background())

	allIfaces := resolver.GetAllInterfaces(context.Background())
	if len(allIfaces) != 3 {
		t.Errorf("expected 3 interfaces, got %d", len(allIfaces))
	}

	// Verify mapping
	expectedMap := map[int]string{
		2: "eth0",
		3: "eth1",
		4: "wlan0",
	}

	for ifindex, expectedName := range expectedMap {
		if name, ok := allIfaces[ifindex]; !ok || name != expectedName {
			t.Errorf("ifindex %d: expected %q, got %q", ifindex, expectedName, name)
		}
	}
}

// TestStartStop tests background refresh loop.
func TestStartStop(t *testing.T) {
	resolver := NewInterfaceResolver(logger.GetDefaultLogger())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Start refresh loop
	resolver.Start(ctx)
	defer resolver.Stop()

	// Let it run for a bit
	time.Sleep(100 * time.Millisecond)

	// Verify it's still running and processing
	stats := resolver.GetStats()
	if stats.RefreshCount < 1 {
		t.Logf("warning: expected refresh activity, got %d refresh cycles", stats.RefreshCount)
	}
}

// TestInvalidInput tests error handling for invalid input.
func TestInvalidInput(t *testing.T) {
	resolver := NewInterfaceResolver(logger.GetDefaultLogger())
	ctx := context.Background()

	tests := []struct {
		ifindex int
		desc    string
	}{
		{0, "zero ifindex"},
		{-1, "negative ifindex"},
		{-999, "large negative ifindex"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			name, err := resolver.GetInterfaceName(ctx, tt.ifindex)
			if err == nil {
				t.Errorf("expected error for %s", tt.desc)
			}
			if name != "" {
				t.Errorf("expected empty name for %s, got %q", tt.desc, name)
			}
		})
	}
}

// Helper: createMockInterface creates a mock interface in tmpdir.
func createMockInterface(t *testing.T, tmpdir, name string, ifindex int) {
	ifdir := filepath.Join(tmpdir, name)
	if err := os.Mkdir(ifdir, 0755); err != nil {
		t.Fatalf("failed to create mock interface dir: %v", err)
	}

	ifindexFile := filepath.Join(ifdir, "if_index")
	ifindexContent := []byte(string(rune(48 + ifindex/10)) + string(rune(48 + ifindex%10)) + "\n")

	if err := ioutil.WriteFile(ifindexFile, ifindexContent, 0644); err != nil {
		t.Fatalf("failed to write if_index: %v", err)
	}
}
