#include <vmlinux.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>
#include <bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Network constants (since they might not be in vmlinux.h)
#define AF_INET 2
#define AF_INET6 10
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

// Network structures (define if not available in vmlinux.h)
struct sockaddr {
    unsigned short sa_family;
    char sa_data[14];
};

struct sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    struct {
        unsigned int s_addr;
    } sin_addr;
    char sin_zero[8];
};

struct sockaddr_in6 {
    unsigned short sin6_family;
    unsigned short sin6_port;
    unsigned int sin6_flowinfo;
    struct {
        union {
            unsigned char s6_addr[16];
            unsigned short s6_addr16[8];
            unsigned int s6_addr32[4];
        };
    } sin6_addr;
    unsigned int sin6_scope_id;
};

struct event_t {
    u32 pid;
    u64 ts;
    u32 ret;  // Changed from int to u32 for better alignment
    char comm[16];
    u32 dest_ip;   // IPv4 address (0 if IPv6)
    u8 dest_ip6[16]; // IPv6 address (all zeros if IPv4)
    u16 dest_port; // Destination port
    u16 family;    // Address family (AF_INET, AF_INET6)
    u8 protocol;   // Protocol (IPPROTO_TCP, IPPROTO_UDP)
    u8 sock_type;  // Socket type (SOCK_STREAM, SOCK_DGRAM)
    u16 padding;   // Explicit padding for alignment
} __attribute__((packed)); // Force no padding

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// ============================================================================
// CONNECTION LIFECYCLE TRACKING - Track packets and connection duration
// ============================================================================

// Key to identify a connection: (pid, file descriptor)
struct conn_key_t {
    u32 pid;
    int fd;
} __attribute__((packed));

// State tracked for each active connection
struct conn_state_t {
    u64 start_ns;        // When connect() was called
    u64 first_pkt_ns;    // When first packet was sent/received
    u64 last_pkt_ns;     // When last packet was sent/received
    u64 pkts_sent;       // Count of write/sendmsg calls
    u64 pkts_recv;       // Count of read/recvmsg calls
    u32 dest_ip;         // Destination IPv4
    u8  dest_ip6[16];    // Destination IPv6
    u16 dest_port;       // Destination port
    u16 family;          // AF_INET or AF_INET6
    u8  protocol;        // IPPROTO_TCP or IPPROTO_UDP
    u8  pad[7];          // Alignment padding
} __attribute__((packed));

// Map to track active connections: (pid, fd) -> connection state
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct conn_key_t);
    __type(value, struct conn_state_t);
} active_conns SEC(".maps");

// Per-CPU scratch space to pass fd from sys_enter_* to sys_exit_*
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, int);
} scratch_fd SEC(".maps");

// Event structure for connection close with complete stats
struct close_event_t {
    u32 pid;             // Process ID
    u64 start_ns;        // When connection was established
    u64 first_pkt_ns;    // When first packet was sent/received
    u64 last_pkt_ns;     // When last packet was sent/received
    u64 pkts_sent;       // Number of packets sent
    u64 pkts_recv;       // Number of packets received
    u32 dest_ip;         // Destination IPv4
    u8  dest_ip6[16];    // Destination IPv6
    u16 dest_port;       // Destination port
    u16 family;          // Address family
    u8  protocol;        // Protocol type
    u8  pad[1];          // Alignment
} __attribute__((packed));

// Ring buffer for close events (4MB)
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} close_events SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    // bpf_ktime_get_ns() returns nanoseconds since boot - this will be
    // converted to wall-clock time in userspace using system boot time
    e->ts = bpf_ktime_get_ns();
    e->ret = 0; // Initialize ret field
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Extract destination IP and port from connect() syscall arguments
    // ctx->args[0] = socket fd
    // ctx->args[1] = struct sockaddr *addr
    // ctx->args[2] = socklen_t addrlen
    
    // Initialize all fields
    e->protocol = 0;
    e->sock_type = 0;
    e->padding = 0;
    e->dest_ip = 0;
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        e->dest_ip6[i] = 0;
    }
    
    // Try to determine protocol from socket - this is tricky in eBPF
    // We'll use a heuristic based on the destination port for common protocols
    struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
    if (addr) {
        u16 family;
        if (bpf_probe_read_user(&family, sizeof(family), &addr->sa_family) == 0) {
            e->family = family;
            
            if (family == AF_INET) {
                struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
                if (bpf_probe_read_user(&e->dest_ip, sizeof(e->dest_ip), &addr_in->sin_addr.s_addr) != 0) {
                    e->dest_ip = 0;
                }
                if (bpf_probe_read_user(&e->dest_port, sizeof(e->dest_port), &addr_in->sin_port) != 0) {
                    e->dest_port = 0;
                } else {
                    e->dest_port = __builtin_bswap16(e->dest_port); // Convert from network to host byte order
                    
                    // Heuristic protocol detection based on common ports
                    // Most connect() calls on these ports are TCP
                    if (e->dest_port == 80 || e->dest_port == 443 || e->dest_port == 22 || 
                        e->dest_port == 21 || e->dest_port == 25 || e->dest_port == 993 || 
                        e->dest_port == 995 || e->dest_port == 587 || e->dest_port == 143 ||
                        e->dest_port == 110 || e->dest_port == 3306 || e->dest_port == 5432) {
                        e->protocol = IPPROTO_TCP;
                        e->sock_type = SOCK_STREAM;
                    } else if (e->dest_port == 53 || e->dest_port == 67 || e->dest_port == 68 ||
                               e->dest_port == 123 || e->dest_port == 161 || e->dest_port == 162) {
                        e->protocol = IPPROTO_UDP;
                        e->sock_type = SOCK_DGRAM;
                    } else {
                        // Default assumption: most connect() calls are TCP
                        e->protocol = IPPROTO_TCP;
                        e->sock_type = SOCK_STREAM;
                    }
                }
            } else if (family == AF_INET6) {
                struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
                // Copy IPv6 address
                if (bpf_probe_read_user(&e->dest_ip6, sizeof(e->dest_ip6), &addr_in6->sin6_addr.s6_addr) != 0) {
                    // Clear IPv6 address on failure
                    #pragma unroll
                    for (int i = 0; i < 16; i++) {
                        e->dest_ip6[i] = 0;
                    }
                }
                if (bpf_probe_read_user(&e->dest_port, sizeof(e->dest_port), &addr_in6->sin6_port) != 0) {
                    e->dest_port = 0;
                } else {
                    e->dest_port = __builtin_bswap16(e->dest_port); // Convert from network to host byte order
                    
                    // Same protocol detection logic for IPv6
                    if (e->dest_port == 80 || e->dest_port == 443 || e->dest_port == 22 || 
                        e->dest_port == 21 || e->dest_port == 25 || e->dest_port == 993 || 
                        e->dest_port == 995 || e->dest_port == 587 || e->dest_port == 143 ||
                        e->dest_port == 110 || e->dest_port == 3306 || e->dest_port == 5432) {
                        e->protocol = IPPROTO_TCP;
                        e->sock_type = SOCK_STREAM;
                    } else if (e->dest_port == 53 || e->dest_port == 67 || e->dest_port == 68 ||
                               e->dest_port == 123 || e->dest_port == 161 || e->dest_port == 162) {
                        e->protocol = IPPROTO_UDP;
                        e->sock_type = SOCK_DGRAM;
                    } else {
                        // Default assumption: most connect() calls are TCP
                        e->protocol = IPPROTO_TCP;
                        e->sock_type = SOCK_STREAM;
                    }
                }
            } else if (family == AF_INET6) {
                struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
                // Copy IPv6 address
                if (bpf_probe_read_user(&e->dest_ip6, sizeof(e->dest_ip6), &addr_in6->sin6_addr.s6_addr) != 0) {
                    // Clear IPv6 address on failure
                    #pragma unroll
                    for (int i = 0; i < 16; i++) {
                        e->dest_ip6[i] = 0;
                    }
                }
                if (bpf_probe_read_user(&e->dest_port, sizeof(e->dest_port), &addr_in6->sin6_port) != 0) {
                    e->dest_port = 0;
                } else {
                    e->dest_port = __builtin_bswap16(e->dest_port); // Convert from network to host byte order
                    
                    // Same protocol detection logic for IPv6
                    if (e->dest_port == 80 || e->dest_port == 443 || e->dest_port == 22 || 
                        e->dest_port == 21 || e->dest_port == 25 || e->dest_port == 993 || 
                        e->dest_port == 995 || e->dest_port == 587 || e->dest_port == 143 ||
                        e->dest_port == 110 || e->dest_port == 3306 || e->dest_port == 5432) {
                        e->protocol = IPPROTO_TCP;
                        e->sock_type = SOCK_STREAM;
                    } else if (e->dest_port == 53 || e->dest_port == 67 || e->dest_port == 68 ||
                               e->dest_port == 123 || e->dest_port == 161 || e->dest_port == 162) {
                        e->protocol = IPPROTO_UDP;
                        e->sock_type = SOCK_DGRAM;
                    } else {
                        // Default assumption: most connect() calls are TCP
                        e->protocol = IPPROTO_TCP;
                        e->sock_type = SOCK_STREAM;
                    }
                }
            } else {
                // Unknown address family - already cleared above
            }
        } else {
            e->family = 0;
            e->dest_ip = 0;
            e->dest_port = 0;
        }
    } else {
        e->family = 0;
        e->dest_ip = 0;
        e->dest_port = 0;
    }

    // Store connection in tracking map for lifecycle monitoring
    int fd = (int)ctx->args[0];
    struct conn_key_t conn_key = { .pid = e->pid, .fd = fd };
    struct conn_state_t conn_state = {
        .start_ns      = e->ts,
        .first_pkt_ns  = 0,
        .last_pkt_ns   = 0,
        .pkts_sent     = 0,
        .pkts_recv     = 0,
        .dest_ip       = e->dest_ip,
        .dest_port     = e->dest_port,
        .family        = e->family,
        .protocol      = e->protocol,
    };

    // Copy IPv6 address
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        conn_state.dest_ip6[i] = e->dest_ip6[i];
    }

    bpf_map_update_elem(&active_conns, &conn_key, &conn_state, BPF_ANY);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// ============================================================================
// TRACEPOINT: sys_enter_connect - Store connection state
// ============================================================================

// Note: trace_connect is already defined above

// ============================================================================
// TRACEPOINT: sys_enter_write - Capture fd for write tracking
// ============================================================================

SEC("tracepoint/syscalls/sys_enter_write")
int trace_enter_write(struct trace_event_raw_sys_enter *ctx) {
    // ctx->args[0] = fd
    // Store fd in per-cpu scratch for sys_exit_write to use
    int fd = (int)ctx->args[0];
    u32 zero = 0;
    bpf_map_update_elem(&scratch_fd, &zero, &fd, BPF_ANY);
    return 0;
}

// ============================================================================
// TRACEPOINT: sys_exit_write - Update packet tracking
// ============================================================================

SEC("tracepoint/syscalls/sys_exit_write")
int trace_exit_write(struct trace_event_raw_sys_exit *ctx) {
    // Track write syscall exits - update packet tracking

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 zero = 0;

    // Get fd from scratch space
    int *fd_ptr = bpf_map_lookup_elem(&scratch_fd, &zero);
    if (!fd_ptr) return 0;
    int fd = *fd_ptr;

    // Look up connection state
    struct conn_key_t key = { .pid = pid, .fd = fd };
    struct conn_state_t *state = bpf_map_lookup_elem(&active_conns, &key);
    if (!state) return 0;

    u64 now = bpf_ktime_get_ns();

    // Update packet tracking
    if (state->first_pkt_ns == 0) {
        state->first_pkt_ns = now;
    }
    state->last_pkt_ns = now;
    state->pkts_sent++;

    return 0;
}

// ============================================================================
// TRACEPOINT: sys_enter_read - Capture fd for read tracking
// ============================================================================

SEC("tracepoint/syscalls/sys_enter_read")
int trace_enter_read(struct trace_event_raw_sys_enter *ctx) {
    // ctx->args[0] = fd
    int fd = (int)ctx->args[0];
    u32 zero = 0;
    bpf_map_update_elem(&scratch_fd, &zero, &fd, BPF_ANY);
    return 0;
}

// ============================================================================
// TRACEPOINT: sys_exit_read - Update packet tracking
// ============================================================================

SEC("tracepoint/syscalls/sys_exit_read")
int trace_exit_read(struct trace_event_raw_sys_exit *ctx) {
    // Track read syscall exits - update packet tracking

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 zero = 0;

    // Get fd from scratch space
    int *fd_ptr = bpf_map_lookup_elem(&scratch_fd, &zero);
    if (!fd_ptr) return 0;
    int fd = *fd_ptr;

    // Look up connection state
    struct conn_key_t key = { .pid = pid, .fd = fd };
    struct conn_state_t *state = bpf_map_lookup_elem(&active_conns, &key);
    if (!state) return 0;

    u64 now = bpf_ktime_get_ns();

    // Update packet tracking
    if (state->first_pkt_ns == 0) {
        state->first_pkt_ns = now;
    }
    state->last_pkt_ns = now;
    state->pkts_recv++;

    return 0;
}

// ============================================================================
// TRACEPOINT: sys_enter_close - Capture fd for close tracking
// ============================================================================

SEC("tracepoint/syscalls/sys_enter_close")
int trace_enter_close(struct trace_event_raw_sys_enter *ctx) {
    // ctx->args[0] = fd
    int fd = (int)ctx->args[0];
    u32 zero = 0;
    bpf_map_update_elem(&scratch_fd, &zero, &fd, BPF_ANY);
    return 0;
}

// ============================================================================
// TRACEPOINT: sys_exit_close - Emit close event with final stats
// ============================================================================

SEC("tracepoint/syscalls/sys_exit_close")
int trace_exit_close(struct trace_event_raw_sys_exit *ctx) {
    // Emit close event to finalize connection tracking
    // We capture at sys_exit regardless of success/failure

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u32 zero = 0;

    // Get fd from scratch space
    int *fd_ptr = bpf_map_lookup_elem(&scratch_fd, &zero);
    if (!fd_ptr) return 0;
    int fd = *fd_ptr;

    // Look up connection state
    struct conn_key_t key = { .pid = pid, .fd = fd };
    struct conn_state_t *state = bpf_map_lookup_elem(&active_conns, &key);
    if (!state) return 0;

    // Only emit if there was actual packet traffic
    if (state->pkts_sent > 0 || state->pkts_recv > 0) {
        struct close_event_t *e = bpf_ringbuf_reserve(&close_events, sizeof(*e), 0);
        if (e) {
            e->pid           = pid;
            e->start_ns      = state->start_ns;
            e->first_pkt_ns  = state->first_pkt_ns;
            e->last_pkt_ns   = state->last_pkt_ns;
            e->pkts_sent     = state->pkts_sent;
            e->pkts_recv     = state->pkts_recv;
            e->dest_ip       = state->dest_ip;
            e->dest_port     = state->dest_port;
            e->family        = state->family;
            e->protocol      = state->protocol;

            // Copy IPv6 address
            #pragma unroll
            for (int i = 0; i < 16; i++) {
                e->dest_ip6[i] = state->dest_ip6[i];
            }

            bpf_ringbuf_submit(e, 0);
        }
    }

    // Remove connection from tracking
    bpf_map_delete_elem(&active_conns, &key);
    return 0;
}
