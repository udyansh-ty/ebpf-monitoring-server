package aggregator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/srodi/ebpf-server/internal/core"
	"github.com/srodi/ebpf-server/internal/storage"
)

type metaWindowTestStorage struct {
	upsertErr        error
	rows             []storage.EBPFMetaWindowRow
	calls            int
	retentionErr     error
	retentionCalls   int
	retentionWindow  int64
	retentionDeleted int64
}

func (s *metaWindowTestStorage) Store(context.Context, core.Event) error {
	return nil
}

func (s *metaWindowTestStorage) Query(context.Context, core.Query) ([]core.Event, error) {
	return nil, nil
}

func (s *metaWindowTestStorage) Count(context.Context, core.Query) (int, error) {
	return 0, nil
}

func (s *metaWindowTestStorage) UpsertMetaWindowRows(_ context.Context, rows []storage.EBPFMetaWindowRow) error {
	s.calls++
	s.rows = append(s.rows, rows...)
	return s.upsertErr
}

func (s *metaWindowTestStorage) DeleteMetaWindowOlderThan(_ context.Context, keepWindowSeconds int64) (int64, error) {
	s.retentionCalls++
	s.retentionWindow = keepWindowSeconds
	return s.retentionDeleted, s.retentionErr
}

func (s *metaWindowTestStorage) rowsByKey() map[metaRollupKey]storage.EBPFMetaWindowRow {
	out := make(map[metaRollupKey]storage.EBPFMetaWindowRow, len(s.rows))
	for _, row := range s.rows {
		key := metaRollupKey{
			BucketEpoch: row.BucketEpoch,
			SrcIP:       row.SrcIP,
			DstIP:       row.DstIP,
			SNI:         row.SNI,
		}
		out[key] = row
	}
	return out
}

func TestTrackMetaWindowRollupAggregatesByMinuteAndPair(t *testing.T) {
	agg, err := New(&Config{})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	first := map[string]interface{}{
		"type":             "connection",
		"src_ip":           "192.168.1.25",
		"dst_ip":           "142.250.183.69",
		"duration_ms":      float64(3000),
		"packets_incoming": float64(12),
		"packets_outgoing": float64(20),
		"session_start_ns": float64(1773919447000000000),
		"session_end_ns":   float64(1773919458000000000),
	}
	second := map[string]interface{}{
		"type":             "connection",
		"src_ip":           "192.168.1.25",
		"dst_ip":           "142.250.183.69",
		"duration_ms":      float64(2000),
		"packets_incoming": float64(8),
		"packets_outgoing": float64(14),
		"session_start_ns": float64(1773919465000000000),
		"session_end_ns":   float64(1773919478000000000),
	}

	agg.trackMetaWindowRollup(first)
	agg.trackMetaWindowRollup(second)

	agg.metaMu.RLock()
	defer agg.metaMu.RUnlock()

	if len(agg.metaRollups) != 1 {
		t.Fatalf("expected 1 rollup key, got %d", len(agg.metaRollups))
	}

	key := metaRollupKey{
		BucketEpoch: 1773919440,
		SrcIP:       "192.168.1.25",
		DstIP:       "142.250.183.69",
	}
	entry, ok := agg.metaRollups[key]
	if !ok {
		t.Fatalf("expected rollup entry for key %+v", key)
	}
	if entry.ActiveSeconds != 5 {
		t.Fatalf("expected active_seconds=5, got %d", entry.ActiveSeconds)
	}
	if entry.PacketsIn != 20 {
		t.Fatalf("expected packets_in=20, got %d", entry.PacketsIn)
	}
	if entry.PacketsOut != 34 {
		t.Fatalf("expected packets_out=34, got %d", entry.PacketsOut)
	}
	if entry.SessionCount != 2 {
		t.Fatalf("expected session_count=2, got %d", entry.SessionCount)
	}
	if entry.FirstSeenEpoch != 1773919447 {
		t.Fatalf("expected first_seen_epoch=1773919447, got %d", entry.FirstSeenEpoch)
	}
	if entry.LastSeenEpoch != 1773919478 {
		t.Fatalf("expected last_seen_epoch=1773919478, got %d", entry.LastSeenEpoch)
	}
}

func TestTrackMetaWindowRollupSkipsNonSessionConnectionEvents(t *testing.T) {
	agg, err := New(&Config{})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	agg.trackMetaWindowRollup(map[string]interface{}{
		"type":        "connection",
		"src_ip":      "192.168.1.25",
		"dst_ip":      "142.250.183.69",
		"duration_ms": float64(1500),
	})

	agg.metaMu.RLock()
	defer agg.metaMu.RUnlock()
	if len(agg.metaRollups) != 0 {
		t.Fatalf("expected no rollups for non-session event, got %d", len(agg.metaRollups))
	}
}

func TestTrackMetaWindowRollupSupportsNestedMetadataAndAliases(t *testing.T) {
	agg, err := New(&Config{})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	agg.trackMetaWindowRollup(map[string]interface{}{
		"type": "connection",
		"metadata": map[string]interface{}{
			"source_ip":        "192.168.1.25",
			"destination_ip":   "142.250.183.69",
			"duration_ms":      float64(2500),
			"incoming_packets": float64(9),
			"outgoing_packets": float64(11),
			"session_start_ns": float64(1773919447000000000),
			"session_end_ns":   float64(1773919452000000000),
			"tls": map[string]interface{}{
				"server_name": "MAIL.GOOGLE.COM",
			},
		},
	})

	agg.metaMu.RLock()
	defer agg.metaMu.RUnlock()
	if len(agg.metaRollups) != 1 {
		t.Fatalf("expected one rollup for nested metadata, got %d", len(agg.metaRollups))
	}

	key := metaRollupKey{
		BucketEpoch: 1773919440,
		SrcIP:       "192.168.1.25",
		DstIP:       "142.250.183.69",
		SNI:         "mail.google.com",
	}
	entry, ok := agg.metaRollups[key]
	if !ok {
		t.Fatalf("expected rollup entry for key %+v", key)
	}
	if entry.PacketsIn != 9 || entry.PacketsOut != 11 {
		t.Fatalf("unexpected packet totals for nested metadata: %+v", entry)
	}
}

func TestTrackMetaWindowRollupFallsBackToObservedTimestamp(t *testing.T) {
	agg, err := New(&Config{})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	agg.trackMetaWindowRollup(map[string]interface{}{
		"event_type": "connection",
		"metadata": map[string]interface{}{
			"src_ip":      "10.10.10.10:51000",
			"dst_ip":      "142.250.183.69:443",
			"observed_at": float64(1773919458000000000),
			"packets_in":  float64(3),
			"packets_out": float64(5),
			"host":        "https://mail.google.com/mail/u/0",
		},
	})

	agg.metaMu.RLock()
	defer agg.metaMu.RUnlock()
	if len(agg.metaRollups) != 1 {
		t.Fatalf("expected one rollup with observed_at fallback, got %d", len(agg.metaRollups))
	}

	key := metaRollupKey{
		BucketEpoch: 1773919440,
		SrcIP:       "10.10.10.10",
		DstIP:       "142.250.183.69",
		SNI:         "mail.google.com",
	}
	entry, ok := agg.metaRollups[key]
	if !ok {
		t.Fatalf("expected rollup entry for key %+v", key)
	}
	if entry.FirstSeenEpoch != 1773919458 || entry.LastSeenEpoch != 1773919458 {
		t.Fatalf("expected first/last seen derived from observed_at, got %+v", entry)
	}
	if entry.SessionCount != 1 {
		t.Fatalf("expected session_count=1, got %d", entry.SessionCount)
	}
}

func TestTrackMetaWindowRollupSeparatesBySNI(t *testing.T) {
	agg, err := New(&Config{})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	base := map[string]interface{}{
		"type":             "connection",
		"src_ip":           "192.168.1.25",
		"dst_ip":           "142.250.183.69",
		"duration_ms":      float64(1000),
		"packets_incoming": float64(4),
		"packets_outgoing": float64(6),
		"session_start_ns": float64(1773919447000000000),
		"session_end_ns":   float64(1773919458000000000),
	}

	first := make(map[string]interface{}, len(base)+1)
	for k, v := range base {
		first[k] = v
	}
	first["sni"] = "mail.google.com"

	second := make(map[string]interface{}, len(base)+1)
	for k, v := range base {
		second[k] = v
	}
	second["sni"] = "www.youtube.com"

	agg.trackMetaWindowRollup(first)
	agg.trackMetaWindowRollup(second)

	agg.metaMu.RLock()
	defer agg.metaMu.RUnlock()
	if len(agg.metaRollups) != 2 {
		t.Fatalf("expected 2 rollup keys split by sni, got %d", len(agg.metaRollups))
	}
}

func TestPruneMetaRollupsRemovesExpiredKeys(t *testing.T) {
	agg, err := New(&Config{MetaWindow: 10 * time.Minute})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	now := time.Now().UTC().Unix()
	agg.metaRollups[metaRollupKey{BucketEpoch: now - 720, SrcIP: "10.0.0.1", DstIP: "8.8.8.8"}] = &metaRollupAggregate{
		LastSeenEpoch: now - 700,
	}
	agg.metaRollups[metaRollupKey{BucketEpoch: now - 120, SrcIP: "10.0.0.2", DstIP: "1.1.1.1"}] = &metaRollupAggregate{
		LastSeenEpoch: now - 60,
	}

	agg.pruneMetaRollups(now)

	agg.metaMu.RLock()
	defer agg.metaMu.RUnlock()
	if len(agg.metaRollups) != 1 {
		t.Fatalf("expected 1 rollup after prune, got %d", len(agg.metaRollups))
	}
	for _, entry := range agg.metaRollups {
		if entry.LastSeenEpoch < now-600 {
			t.Fatalf("found expired rollup that should have been pruned: %+v", entry)
		}
	}
}

func TestFlushMetaRollupsBatchesAndDrains(t *testing.T) {
	testStorage := &metaWindowTestStorage{}
	agg, err := New(&Config{
		Storage: testStorage,
	})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	agg.metaMu.Lock()
	agg.metaRollups[metaRollupKey{
		BucketEpoch: 1773919440,
		SrcIP:       "192.168.1.25",
		DstIP:       "142.250.183.69",
	}] = &metaRollupAggregate{
		ActiveSeconds:  12,
		PacketsIn:      23,
		PacketsOut:     44,
		SessionCount:   2,
		FirstSeenEpoch: 1773919447,
		LastSeenEpoch:  1773919478,
	}
	agg.metaRollups[metaRollupKey{
		BucketEpoch: 1773919500,
		SrcIP:       "10.0.0.2",
		DstIP:       "8.8.8.8",
	}] = &metaRollupAggregate{
		ActiveSeconds:  7,
		PacketsIn:      11,
		PacketsOut:     15,
		SessionCount:   1,
		FirstSeenEpoch: 1773919503,
		LastSeenEpoch:  1773919509,
	}
	agg.metaMu.Unlock()

	agg.flushMetaRollups(context.Background(), 1773919510)

	if testStorage.calls != 1 {
		t.Fatalf("expected one batch upsert call, got %d", testStorage.calls)
	}
	if len(testStorage.rows) != 2 {
		t.Fatalf("expected two flushed rows, got %d", len(testStorage.rows))
	}

	rows := testStorage.rowsByKey()
	key := metaRollupKey{
		BucketEpoch: 1773919440,
		SrcIP:       "192.168.1.25",
		DstIP:       "142.250.183.69",
	}
	row, ok := rows[key]
	if !ok {
		t.Fatalf("missing flushed row for key %+v", key)
	}
	if row.SessionCount != 2 || row.PacketsIn != 23 || row.PacketsOut != 44 {
		t.Fatalf("unexpected flushed row values: %+v", row)
	}

	agg.metaMu.RLock()
	defer agg.metaMu.RUnlock()
	if len(agg.metaRollups) != 0 {
		t.Fatalf("expected in-memory rollups to be drained after successful flush, got %d", len(agg.metaRollups))
	}
}

func TestFlushMetaRollupsRequeuesOnFailure(t *testing.T) {
	testStorage := &metaWindowTestStorage{
		upsertErr: errors.New("db unavailable"),
	}
	agg, err := New(&Config{
		Storage: testStorage,
	})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	agg.metaMu.Lock()
	agg.metaRollups[metaRollupKey{
		BucketEpoch: 1773919440,
		SrcIP:       "192.168.1.25",
		DstIP:       "142.250.183.69",
	}] = &metaRollupAggregate{
		ActiveSeconds:  9,
		PacketsIn:      18,
		PacketsOut:     30,
		SessionCount:   3,
		FirstSeenEpoch: 1773919447,
		LastSeenEpoch:  1773919478,
	}
	agg.metaMu.Unlock()

	agg.flushMetaRollups(context.Background(), 1773919510)

	if testStorage.calls != 1 {
		t.Fatalf("expected one batch upsert attempt, got %d", testStorage.calls)
	}

	agg.metaMu.RLock()
	defer agg.metaMu.RUnlock()
	if len(agg.metaRollups) != 1 {
		t.Fatalf("expected rollup to be restored after flush failure, got %d", len(agg.metaRollups))
	}

	key := metaRollupKey{
		BucketEpoch: 1773919440,
		SrcIP:       "192.168.1.25",
		DstIP:       "142.250.183.69",
	}
	entry, ok := agg.metaRollups[key]
	if !ok {
		t.Fatalf("expected restored rollup key %+v", key)
	}
	if entry.SessionCount != 3 || entry.PacketsIn != 18 || entry.PacketsOut != 30 {
		t.Fatalf("unexpected restored rollup values: %+v", entry)
	}
}

func TestRunMetaWindowRetentionUsesConfiguredWindow(t *testing.T) {
	testStorage := &metaWindowTestStorage{
		retentionDeleted: 4,
	}
	agg, err := New(&Config{
		Storage:    testStorage,
		MetaWindow: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	agg.runMetaWindowRetention(context.Background())

	if testStorage.retentionCalls != 1 {
		t.Fatalf("expected one retention call, got %d", testStorage.retentionCalls)
	}
	if testStorage.retentionWindow != 600 {
		t.Fatalf("expected retention window 600 seconds, got %d", testStorage.retentionWindow)
	}
}

func TestRunMetaWindowRetentionUsesDefaultWindow(t *testing.T) {
	testStorage := &metaWindowTestStorage{}
	agg, err := New(&Config{
		Storage: testStorage,
	})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	agg.runMetaWindowRetention(context.Background())

	if testStorage.retentionCalls != 1 {
		t.Fatalf("expected one retention call, got %d", testStorage.retentionCalls)
	}
	if testStorage.retentionWindow != 600 {
		t.Fatalf("expected default retention window 600 seconds, got %d", testStorage.retentionWindow)
	}
}
