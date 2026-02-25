#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#ifdef __TARGET_ARCH_x86
#define bpf_target_x86
#define bpf_target_defined
#elif defined(__TARGET_ARCH_arm64)
#define bpf_target_arm64
#define bpf_target_defined
#endif

/* Basic type definitions for eBPF programs */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long long s64;

// ANCHOR: __u* typedefs for BPF headers - Build fix - Feb 25, 2026
// Provide __u* aliases expected by system BPF headers when using minimal vmlinux.h.
typedef u8 __u8;
typedef u16 __u16;
typedef u32 __u32;
typedef u64 __u64;
typedef s8 __s8;
typedef s16 __s16;
typedef s32 __s32;
typedef s64 __s64;

// ANCHOR: Network Type Aliases - Build fix - Feb 25, 2026
// Provide minimal big-endian and checksum aliases expected by headers.
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;

// ANCHOR: Minimal Networking Structures - Build fix - Feb 25, 2026
// Provide UAPI-compatible structs used by TC classifier parsing.
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMPV6 58

struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
	__u32 napi_id;
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_ip6[4];
	__u32 local_ip6[4];
	__u32 remote_port;
	__u32 local_port;
	__u32 data_meta;
	__u32 flow_keys;
	__u32 tstamp;
	__u32 wire_len;
	__u32 gso_segs;
	__u32 gso_size;
};

struct ethhdr {
	__u8 h_dest[6];
	__u8 h_source[6];
	__be16 h_proto;
};

struct iphdr {
	__u8 ihl:4,
	     version:4;
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__be16 check;
	__be32 saddr;
	__be32 daddr;
};

struct in6_addr {
	union {
		__u8 u6_addr8[16];
		__u16 u6_addr16[8];
		__u32 u6_addr32[4];
	} in6_u;
};

struct ipv6hdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	__u8 priority:4,
	     version:4;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	__u8 version:4,
	     priority:4;
#else
#error "Unknown byte order"
#endif
	__u8 flow_lbl[3];
	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	struct in6_addr saddr;
	struct in6_addr daddr;
};

/* Process/task related structures */
struct trace_event_raw_sys_enter {
    u16 common_type;
    u8 common_flags;
    u8 common_preempt_count;
    s32 common_pid;
    s32 id;
    unsigned long args[6];
};

/* Basic kernel structures needed for eBPF */
struct task_struct {
    int pid;
    int tgid;
    char comm[16];
};

/* Socket and network structures (simplified) */
struct sock {
    u16 sk_family;
    u16 sk_type;
    u32 sk_rcvbuf;
    u32 sk_sndbuf;
};

struct sk_buff {
    u32 len;
    u32 data_len;
    u16 mac_len;
    u16 hdr_len;
    u32 priority;
    u32 mark;
};

/* Time structures */
typedef u64 ktime_t;

#endif /* __VMLINUX_H__ */
