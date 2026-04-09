#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct trace_event_raw_kfree_skb {
	u16 common_type;
	u8 common_flags;
	u8 common_preempt_count;
	s32 common_pid;
	void *skbaddr;
	void *location;
	u16 protocol;
	u16 reason;
};

// Packet drop event structure
struct drop_event_t {
	u32 pid;         // Process ID (can be 0 in kernel-context drops)
	u64 ts;          // Timestamp (nanoseconds since boot)
	char comm[16];   // Command name
	u32 drop_reason; // Drop reason code
	u32 skb_len;     // Socket buffer length (when available)
	u8 padding[8];   // Padding for alignment
} __attribute__((packed)); // Force no padding

// Ring buffer for packet drop events
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024); // 256KB ring buffer
} drop_events SEC(".maps");

// Tracepoint for kfree_skb (packet drops)
SEC("tracepoint/skb/kfree_skb")
int trace_kfree_skb(struct trace_event_raw_kfree_skb *ctx) {
	struct drop_event_t *event;
	u64 pid_tgid;
	u32 pid;

	// Get current task info (may be pid=0 for softirq/kernel-context drops).
	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;

	// Reserve space in ring buffer
	event = bpf_ringbuf_reserve(&drop_events, sizeof(*event), 0);
	if (!event)
		return 0;

	// Initialize event structure
	__builtin_memset(event, 0, sizeof(*event));

	// Fill basic event information
	event->pid = pid;
	// bpf_ktime_get_ns() returns nanoseconds since boot - this will be
	// converted to wall-clock time in userspace using system boot time
	event->ts = bpf_ktime_get_ns();
	event->drop_reason = ctx->reason ? ctx->reason : 1;
	event->skb_len = 1; // Mark as valid drop event

	// Get command name
	bpf_get_current_comm(event->comm, sizeof(event->comm));

	// Submit event to ring buffer
	bpf_ringbuf_submit(event, 0);
	return 0;
}

// Alternative: Monitor failed socket operations
SEC("kprobe/tcp_drop")
int trace_tcp_drop(struct pt_regs *ctx) {
	struct drop_event_t *event;
	u64 pid_tgid;
	u32 pid;

	// Get current task info
	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;

	// Reserve space in ring buffer
	event = bpf_ringbuf_reserve(&drop_events, sizeof(*event), 0);
	if (!event)
		return 0;

	// Initialize event structure
	__builtin_memset(event, 0, sizeof(*event));

	// Fill basic event information
	event->pid = pid;
	// bpf_ktime_get_ns() returns nanoseconds since boot - this will be
	// converted to wall-clock time in userspace using system boot time
	event->ts = bpf_ktime_get_ns();
	event->drop_reason = 2; // TCP drop
	event->skb_len = 1;     // Mark as valid drop event

	// Get command name
	bpf_get_current_comm(event->comm, sizeof(event->comm));

	// Submit event to ring buffer
	bpf_ringbuf_submit(event, 0);
	return 0;
}
