// Package storage provides event storage implementations.
package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/srodi/ebpf-server/pkg/logger"
)

// ANCHOR: eBPF Query Helpers - Feb 3, 2026
// WHY: Provide specialized query functions for eBPF event analysis (connections, drops, multi-NIC)
// WHAT: Query helper functions for common analysis patterns
// HOW: Build parameterized SQL queries for filtering, aggregation, and multi-NIC analysis

// EBPFQueries provides helper functions for querying eBPF events.
type EBPFQueries struct {
	pool *pgxpool.Pool
}

// NewEBPFQueries creates a new eBPF query helper instance.
func NewEBPFQueries(pool *pgxpool.Pool) *EBPFQueries {
	return &EBPFQueries{
		pool: pool,
	}
}

// ConnectionStats contains aggregated connection statistics.
type ConnectionStats struct {
	TotalConnections int64
	BytesSent        int64
	BytesReceived    int64
	AvgDuration      float64
	UniqueProcesses  int
	UniqueDestIPs    int
}

// DestStat contains destination IP and connection count.
type DestStat struct {
	IP              string
	ConnectionCount int
}

// TimeStat contains timestamp and event count.
type TimeStat struct {
	Timestamp time.Time
	Count     int
}

// GetConnectionStats returns aggregated statistics for connection events.
func (q *EBPFQueries) GetConnectionStats(ctx context.Context, since time.Time) (*ConnectionStats, error) {
	sql := `
		SELECT
			COUNT(*) as total_connections,
			COALESCE(SUM(bytes_sent), 0) as bytes_sent,
			COALESCE(SUM(bytes_received), 0) as bytes_received,
			COALESCE(AVG(duration_ms), 0) as avg_duration,
			COUNT(DISTINCT pid) as unique_processes,
			COUNT(DISTINCT dst_ip) as unique_dest_ips
		FROM ebpf_events
		WHERE event_type = 'connection'
		  AND observed_at >= $1
	`

	var stats ConnectionStats
	err := q.pool.QueryRow(ctx, sql, since).Scan(
		&stats.TotalConnections,
		&stats.BytesSent,
		&stats.BytesReceived,
		&stats.AvgDuration,
		&stats.UniqueProcesses,
		&stats.UniqueDestIPs,
	)

	if err != nil {
		logger.Errorf("Failed to get connection stats: %v", err)
		return nil, fmt.Errorf("failed to get connection stats: %w", err)
	}

	return &stats, nil
}

// PacketDropStats contains aggregated packet drop statistics.
type PacketDropStats struct {
	TotalDropped  int64
	DropReasons   map[string]int64
	AffectedIPs   int
	CriticalDrops int64
}

// GetPacketDropStats returns aggregated statistics for packet drop events.
func (q *EBPFQueries) GetPacketDropStats(ctx context.Context, since time.Time) (*PacketDropStats, error) {
	sql := `
		SELECT
			COALESCE(SUM(dropped_count), 0) as total_dropped,
			drop_reason,
			COUNT(DISTINCT COALESCE(src_ip::text, dst_ip::text)) as affected_ips
		FROM ebpf_events
		WHERE event_type = 'packet_drop'
		  AND observed_at >= $1
		GROUP BY drop_reason
	`

	rows, err := q.pool.Query(ctx, sql, since)
	if err != nil {
		logger.Errorf("Failed to query packet drop stats: %v", err)
		return nil, fmt.Errorf("failed to query packet drop stats: %w", err)
	}
	defer rows.Close()

	stats := &PacketDropStats{
		DropReasons: make(map[string]int64),
	}

	for rows.Next() {
		var totalDropped int64
		var reason string
		var affectedIPs int

		if err := rows.Scan(&totalDropped, &reason, &affectedIPs); err != nil {
			logger.Errorf("Failed to scan drop stats row: %v", err)
			continue
		}

		stats.TotalDropped += totalDropped
		if reason != "" {
			stats.DropReasons[reason] = totalDropped
		}
		stats.AffectedIPs = affectedIPs
	}

	if err = rows.Err(); err != nil {
		logger.Errorf("Row iteration error: %v", err)
		return nil, err
	}

	return stats, nil
}

// ProcessConnectionStats contains per-process connection statistics.
type ProcessConnectionStats struct {
	PID             uint32
	Command         string
	ConnectionCount int
	BytesSent       int64
	BytesReceived   int64
	UniqueDestIPs   int
}

// GetProcessConnectionStats returns connection statistics aggregated by process.
func (q *EBPFQueries) GetProcessConnectionStats(ctx context.Context, limit int) ([]ProcessConnectionStats, error) {
	sql := `
		SELECT
			pid,
			command,
			COUNT(*) as connection_count,
			COALESCE(SUM(bytes_sent), 0) as bytes_sent,
			COALESCE(SUM(bytes_received), 0) as bytes_received,
			COUNT(DISTINCT dst_ip) as unique_dest_ips
		FROM ebpf_events
		WHERE event_type = 'connection'
		GROUP BY pid, command
		ORDER BY connection_count DESC
		LIMIT $1
	`

	rows, err := q.pool.Query(ctx, sql, limit)
	if err != nil {
		logger.Errorf("Failed to query process connection stats: %v", err)
		return nil, fmt.Errorf("failed to query process stats: %w", err)
	}
	defer rows.Close()

	var stats []ProcessConnectionStats
	for rows.Next() {
		var s ProcessConnectionStats
		if err := rows.Scan(&s.PID, &s.Command, &s.ConnectionCount, &s.BytesSent, &s.BytesReceived, &s.UniqueDestIPs); err != nil {
			logger.Errorf("Failed to scan process stats row: %v", err)
			continue
		}
		stats = append(stats, s)
	}

	if err = rows.Err(); err != nil {
		logger.Errorf("Row iteration error: %v", err)
		return nil, err
	}

	return stats, nil
}

// InterfaceStats contains statistics for a specific network interface.
type InterfaceStats struct {
	InterfaceName   string
	EventCount      int
	ConnectionCount int
	DropCount       int
	UniqueProcesses int
	UniqueDestIPs   int
	TotalBytesIn    int64
	TotalBytesOut   int64
}

// GetInterfaceStats returns statistics for a specific interface (multi-NIC support).
// Returns nil if interface_name is not available yet (Phase 1A).
func (q *EBPFQueries) GetInterfaceStats(ctx context.Context, interfaceName string) (*InterfaceStats, error) {
	sql := `
		SELECT
			interface_name,
			COUNT(*) as event_count,
			COALESCE(SUM(CASE WHEN event_type = 'connection' THEN 1 ELSE 0 END), 0) as connection_count,
			COALESCE(SUM(CASE WHEN event_type = 'packet_drop' THEN 1 ELSE 0 END), 0) as drop_count,
			COUNT(DISTINCT pid) as unique_processes,
			COUNT(DISTINCT dst_ip) as unique_dest_ips,
			COALESCE(SUM(bytes_received), 0) as total_bytes_in,
			COALESCE(SUM(bytes_sent), 0) as total_bytes_out
		FROM ebpf_events
		WHERE interface_name = $1
		GROUP BY interface_name
	`

	var stats InterfaceStats
	err := q.pool.QueryRow(ctx, sql, interfaceName).Scan(
		&stats.InterfaceName,
		&stats.EventCount,
		&stats.ConnectionCount,
		&stats.DropCount,
		&stats.UniqueProcesses,
		&stats.UniqueDestIPs,
		&stats.TotalBytesIn,
		&stats.TotalBytesOut,
	)

	if err != nil {
		logger.Errorf("Failed to get interface stats: %v", err)
		return nil, fmt.Errorf("failed to get interface stats: %w", err)
	}

	return &stats, nil
}

// ListInterfaces returns all interfaces that have captured events (multi-NIC support).
func (q *EBPFQueries) ListInterfaces(ctx context.Context) ([]string, error) {
	sql := `
		SELECT DISTINCT interface_name
		FROM ebpf_events
		WHERE interface_name IS NOT NULL
		ORDER BY interface_name
	`

	rows, err := q.pool.Query(ctx, sql)
	if err != nil {
		logger.Errorf("Failed to list interfaces: %v", err)
		return nil, fmt.Errorf("failed to list interfaces: %w", err)
	}
	defer rows.Close()

	var interfaces []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			logger.Errorf("Failed to scan interface name: %v", err)
			continue
		}
		interfaces = append(interfaces, name)
	}

	if err = rows.Err(); err != nil {
		logger.Errorf("Row iteration error: %v", err)
		return nil, err
	}

	return interfaces, nil
}

// ProgramStats contains statistics for a specific eBPF program.
type ProgramStats struct {
	ProgramName     string
	EventCount      int
	EventTypes      map[string]int
	UniqueProcesses int
}

// GetProgramStats returns statistics for a specific eBPF program.
func (q *EBPFQueries) GetProgramStats(ctx context.Context, programName string) (*ProgramStats, error) {
	// Get total events by this program
	sql1 := `
		SELECT COUNT(*) FROM ebpf_events WHERE program_name = $1
	`
	var totalEvents int
	err := q.pool.QueryRow(ctx, sql1, programName).Scan(&totalEvents)
	if err != nil {
		logger.Errorf("Failed to get program event count: %v", err)
		return nil, fmt.Errorf("failed to get program stats: %w", err)
	}

	// Get event breakdown by type
	sql2 := `
		SELECT event_type, COUNT(*) as count
		FROM ebpf_events
		WHERE program_name = $1
		GROUP BY event_type
	`
	rows, err := q.pool.Query(ctx, sql2, programName)
	if err != nil {
		logger.Errorf("Failed to query program event types: %v", err)
		return nil, fmt.Errorf("failed to query event types: %w", err)
	}
	defer rows.Close()

	stats := &ProgramStats{
		ProgramName: programName,
		EventCount:  totalEvents,
		EventTypes:  make(map[string]int),
	}

	for rows.Next() {
		var eventType string
		var count int
		if err := rows.Scan(&eventType, &count); err != nil {
			logger.Errorf("Failed to scan event type: %v", err)
			continue
		}
		stats.EventTypes[eventType] = count
	}

	// Get unique processes
	sql3 := `
		SELECT COUNT(DISTINCT pid) FROM ebpf_events WHERE program_name = $1
	`
	err = q.pool.QueryRow(ctx, sql3, programName).Scan(&stats.UniqueProcesses)
	if err != nil {
		logger.Errorf("Failed to get unique process count: %v", err)
		return nil, fmt.Errorf("failed to get unique processes: %w", err)
	}

	return stats, nil
}

// ListPrograms returns all eBPF programs that have events.
func (q *EBPFQueries) ListPrograms(ctx context.Context) ([]string, error) {
	sql := `
		SELECT DISTINCT program_name
		FROM ebpf_events
		WHERE program_name IS NOT NULL
		ORDER BY program_name
	`

	rows, err := q.pool.Query(ctx, sql)
	if err != nil {
		logger.Errorf("Failed to list programs: %v", err)
		return nil, fmt.Errorf("failed to list programs: %w", err)
	}
	defer rows.Close()

	var programs []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			logger.Errorf("Failed to scan program name: %v", err)
			continue
		}
		programs = append(programs, name)
	}

	if err = rows.Err(); err != nil {
		logger.Errorf("Row iteration error: %v", err)
		return nil, err
	}

	return programs, nil
}

// TopDestinations returns the top destination IPs by connection count.
func (q *EBPFQueries) TopDestinations(ctx context.Context, limit int) ([]DestStat, error) {
	sql := `
		SELECT
			dst_ip::text as ip,
			COUNT(*) as connection_count
		FROM ebpf_events
		WHERE event_type = 'connection'
		  AND dst_ip IS NOT NULL
		GROUP BY dst_ip
		ORDER BY connection_count DESC
		LIMIT $1
	`

	rows, err := q.pool.Query(ctx, sql, limit)
	if err != nil {
		logger.Errorf("Failed to query top destinations: %v", err)
		return nil, fmt.Errorf("failed to query top destinations: %w", err)
	}
	defer rows.Close()

	var results []DestStat
	for rows.Next() {
		var ip string
		var count int
		if err := rows.Scan(&ip, &count); err != nil {
			logger.Errorf("Failed to scan destination: %v", err)
			continue
		}
		results = append(results, DestStat{IP: ip, ConnectionCount: count})
	}

	if err = rows.Err(); err != nil {
		logger.Errorf("Row iteration error: %v", err)
		return nil, err
	}

	return results, nil
}

// ConnectionTimeSeries returns connection count over time (1-minute buckets).
func (q *EBPFQueries) ConnectionTimeSeries(ctx context.Context, since time.Time, until time.Time) ([]TimeStat, error) {
	sql := `
		SELECT
			date_trunc('minute', observed_at) as minute,
			COUNT(*) as count
		FROM ebpf_events
		WHERE event_type = 'connection'
		  AND observed_at >= $1
		  AND observed_at <= $2
		GROUP BY minute
		ORDER BY minute DESC
	`

	rows, err := q.pool.Query(ctx, sql, since, until)
	if err != nil {
		logger.Errorf("Failed to query connection time series: %v", err)
		return nil, fmt.Errorf("failed to query time series: %w", err)
	}
	defer rows.Close()

	var results []TimeStat
	for rows.Next() {
		var ts time.Time
		var count int
		if err := rows.Scan(&ts, &count); err != nil {
			logger.Errorf("Failed to scan time series data: %v", err)
			continue
		}
		results = append(results, TimeStat{Timestamp: ts, Count: count})
	}

	if err = rows.Err(); err != nil {
		logger.Errorf("Row iteration error: %v", err)
		return nil, err
	}

	return results, nil
}
