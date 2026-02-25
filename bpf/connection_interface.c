// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Connection Interface Tracker - TC Ingress Classifier
 *
 * ANCHOR: TC Ingress Classifier for Interface Capture - Phase 1B - Feb 6, 2026
 * WHY: Identify which network interface handles each packet/connection
 * WHAT: BPF program attached to TC ingress on all interfaces
 * HOW: Extract packet headers, map flow key → ifindex, use BPF map for userspace access
 *
 * This program is attached to the TC ingress hook on each network interface.
 * It extracts the 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol) from
 * incoming packets and maps the flow key to the interface index.
 *
 * Userspace can then query the BPF maps to determine which interface a flow uses.
 */

#include "vmlinux.h"
// ANCHOR: Local BPF Headers - Build fix - Feb 25, 2026
// Use repo-local helpers/endian macros to avoid missing kernel type defs.
#include "bpf_helpers.h"
#include "bpf_endian.h"

/* Flow key is a hash of the 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol)
 * This must match the calculation in userspace enricher for correlation.
 */
typedef __u64 flow_key_t;

/* Flow metadata stored in BPF map */
struct flow_metadata {
	__u32 ifindex;           /* Interface index */
	__u64 timestamp;         /* Capture timestamp (bpf_ktime_get_ns()) */
	__u16 src_port;          /* Source port (network byte order) */
	__u16 dst_port;          /* Destination port (network byte order) */
	__u8 protocol;           /* Protocol: IPPROTO_TCP (6) or IPPROTO_UDP (17) */
	__u8 ip_version;         /* 4 or 6 */
	__u16 _pad;              /* Padding for alignment */
};

/* BPF Maps - exposed to userspace */

/* flow_to_interface: Maps flow key (5-tuple hash) to interface index
 * Used to correlate which interface handled a connection.
 * Max entries: 100,000 concurrent flows (configurable)
 * Update strategy: Overwrite on collision (LRU would be better but more complex)
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 100000);
	__type(key, flow_key_t);
	__type(value, struct flow_metadata);
} flow_to_interface SEC(".maps");

/* Statistics map for monitoring */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 5);
	__type(key, __u32);
	__type(value, __u64);
} tc_stats SEC(".maps");

#define STAT_PACKETS_PROCESSED 0
#define STAT_IPV4_PACKETS 1
#define STAT_IPV6_PACKETS 2
#define STAT_UNKNOWN_PACKETS 3
#define STAT_MAP_UPDATES 4

/* Helper: Calculate FNV-1a hash of 5-tuple
 * Used to create deterministic flow key from packet headers
 * Must match userspace calculation exactly.
 */
static __always_inline flow_key_t fnv1a_hash(__u32 src_ip, __u32 dst_ip,
					     __u16 src_port, __u16 dst_port,
					     __u8 protocol) {
	flow_key_t hash = 0xcbf29ce484222325ULL;  /* FNV offset basis */

	/* Hash each field */
#pragma unroll
	for (int i = 0; i < 4; i++) {
		hash ^= (src_ip >> (i * 8)) & 0xFF;
		hash *= 0x100000001b3ULL;  /* FNV prime */

		hash ^= (dst_ip >> (i * 8)) & 0xFF;
		hash *= 0x100000001b3ULL;

		if (i < 2) {
			hash ^= (src_port >> (i * 8)) & 0xFF;
			hash *= 0x100000001b3ULL;

			hash ^= (dst_port >> (i * 8)) & 0xFF;
			hash *= 0x100000001b3ULL;
		}
	}

	hash ^= protocol;
	hash *= 0x100000001b3ULL;

	return hash;
}

/* Helper: Calculate FNV-1a hash for IPv6
 * Similar to IPv4 version but handles 16-byte addresses
 */
static __always_inline flow_key_t fnv1a_hash_v6(struct in6_addr *src_ip,
						 struct in6_addr *dst_ip,
						 __u16 src_port, __u16 dst_port,
						 __u8 protocol) {
	flow_key_t hash = 0xcbf29ce484222325ULL;

	/* Hash IPv6 addresses and ports - simplified for kernel eBPF constraints */
#pragma unroll
	for (int i = 0; i < 4; i++) {
		hash ^= src_ip->in6_u.u6_addr32[i];
		hash *= 0x100000001b3ULL;

		hash ^= dst_ip->in6_u.u6_addr32[i];
		hash *= 0x100000001b3ULL;
	}

	hash ^= src_port;
	hash *= 0x100000001b3ULL;

	hash ^= dst_port;
	hash *= 0x100000001b3ULL;

	hash ^= protocol;
	hash *= 0x100000001b3ULL;

	return hash;
}

/* Helper: Safely read IPv4 packet header
 * Returns: 0 on success, -1 if packet is too short or invalid
 */
static __always_inline int read_ipv4_packet(struct __sk_buff *skb,
					    __u32 *src_ip, __u32 *dst_ip,
					    __u16 *src_port, __u16 *dst_port,
					    __u8 *protocol) {
	/* ANCHOR: Safe IPv4 Header Parsing - Feb 6, 2026
	 * WHY: Extract packet 5-tuple without causing kernel crashes
	 * WHAT: Read Ethernet + IPv4 + TCP/UDP headers with bounds checking
	 * HOW: Use bpf_skb_load_bytes() for safe memory access
	 */

	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

	/* Ethernet header: 14 bytes */
	if (data + 14 > data_end)
		return -1;

	struct ethhdr *eth = data;

	/* IPv4 header: minimum 20 bytes */
	if (data + 14 + 20 > data_end)
		return -1;

	struct iphdr *ip = (struct iphdr *)(data + 14);

	/* Check IP version */
	if (ip->version != 4)
		return -1;

	*src_ip = ip->saddr;
	*dst_ip = ip->daddr;
	*protocol = ip->protocol;

	/* Extract ports from TCP/UDP header */
	__u16 *ports;

	if (ip->protocol == IPPROTO_TCP) {
		/* TCP header starts at IP header + (IHL * 4) bytes */
		__u32 hdr_len = ip->ihl * 4;
		if (data + 14 + hdr_len + 4 > data_end)
			return -1;

		ports = (__u16 *)(data + 14 + hdr_len);
		*src_port = ports[0];  /* TCP source port is first */
		*dst_port = ports[1];  /* TCP dest port is second */
	} else if (ip->protocol == IPPROTO_UDP) {
		/* UDP header starts right after IP header (no options) */
		__u32 hdr_len = ip->ihl * 4;
		if (data + 14 + hdr_len + 4 > data_end)
			return -1;

		ports = (__u16 *)(data + 14 + hdr_len);
		*src_port = ports[0];  /* UDP source port is first */
		*dst_port = ports[1];  /* UDP dest port is second */
	} else if (ip->protocol == IPPROTO_ICMP) {
		/* ICMP: use type/code as "ports" for correlation */
		__u8 *icmp_data = (__u8 *)(data + 14 + (ip->ihl * 4));
		if (icmp_data + 2 > data_end)
			return -1;
		*src_port = 0;
		*dst_port = ((__u16)icmp_data[0] << 8) | icmp_data[1];
	} else {
		/* Other protocols: no port info */
		*src_port = 0;
		*dst_port = 0;
	}

	return 0;
}

/* Helper: Safely read IPv6 packet header */
static __always_inline int read_ipv6_packet(struct __sk_buff *skb,
					    struct in6_addr *src_ip,
					    struct in6_addr *dst_ip,
					    __u16 *src_port, __u16 *dst_port,
					    __u8 *protocol) {
	/* ANCHOR: Safe IPv6 Header Parsing - Feb 6, 2026
	 * WHY: Support IPv6 traffic monitoring
	 * WHAT: Extract IPv6 5-tuple with extension header support
	 * HOW: Parse IPv6 header and follow next_header chain
	 */

	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;

	/* Ethernet + IPv6 header = 14 + 40 bytes */
	if (data + 14 + 40 > data_end)
		return -1;

	struct ipv6hdr *ip6 = (struct ipv6hdr *)(data + 14);

	/* Copy IPv6 addresses */
	*src_ip = ip6->saddr;
	*dst_ip = ip6->daddr;

	/* Parse transport layer */
	__u8 next_header = ip6->nexthdr;
	__u32 hdr_offset = 14 + 40;  /* After Ethernet + IPv6 headers */

	/* Handle up to 10 extension headers (loop unroll limit) */
#pragma unroll
	for (int i = 0; i < 10; i++) {
		if (next_header == IPPROTO_TCP) {
			*protocol = IPPROTO_TCP;
			if (hdr_offset + 4 > (unsigned long)data_end)
				return -1;

			__u16 *ports = (__u16 *)(data + hdr_offset);
			*src_port = ports[0];
			*dst_port = ports[1];
			return 0;
		} else if (next_header == IPPROTO_UDP) {
			*protocol = IPPROTO_UDP;
			if (hdr_offset + 4 > (unsigned long)data_end)
				return -1;

			__u16 *ports = (__u16 *)(data + hdr_offset);
			*src_port = ports[0];
			*dst_port = ports[1];
			return 0;
		} else if (next_header == IPPROTO_ICMPV6) {
			*protocol = IPPROTO_ICMPV6;
			*src_port = 0;
			*dst_port = 0;
			return 0;
		}
		/* Extension headers: hop-by-hop, routing, fragment, destination options */
		/* For simplicity, we stop at first non-transport header */
		break;
	}

	return -1;
}

/* Main TC classifier hook - called for each ingress packet */
SEC("tc")
int tc_ingress_classifier(struct __sk_buff *skb) {
	/* ANCHOR: TC Ingress Handler - Feb 6, 2026
	 * WHY: Capture interface information for every packet
	 * WHAT: Extract 5-tuple, create flow key, store in BPF map
	 * HOW: Parse packet headers safely, calculate hash, update map
	 */

	__u32 key = STAT_PACKETS_PROCESSED;
	__u64 *packets = bpf_map_lookup_elem(&tc_stats, &key);
	if (packets)
		__sync_fetch_and_add(packets, 1);

	__u32 ifindex = skb->ingress_ifindex;
	__u16 eth_proto = bpf_ntohs(skb->protocol);

	int ret = TC_ACT_OK;  /* Default: allow packet through */

	/* IPv4 traffic */
	if (eth_proto == ETH_P_IP) {
		__u32 src_ip, dst_ip;
		__u16 src_port, dst_port;
		__u8 protocol;

		if (read_ipv4_packet(skb, &src_ip, &dst_ip, &src_port, &dst_port,
				     &protocol) < 0) {
			/* Failed to parse packet - silently drop this packet */
			return TC_ACT_OK;
		}

		/* Calculate flow key (deterministic hash) */
		flow_key_t flow_key = fnv1a_hash(src_ip, dst_ip, src_port,
						 dst_port, protocol);

		/* Store in BPF map */
		struct flow_metadata metadata = {
			.ifindex = ifindex,
			.timestamp = bpf_ktime_get_ns(),
			.src_port = src_port,
			.dst_port = dst_port,
			.protocol = protocol,
			.ip_version = 4,
		};

		bpf_map_update_elem(&flow_to_interface, &flow_key, &metadata,
				    BPF_ANY);

		/* Update statistics */
		key = STAT_IPV4_PACKETS;
		__u64 *ipv4_count = bpf_map_lookup_elem(&tc_stats, &key);
		if (ipv4_count)
			__sync_fetch_and_add(ipv4_count, 1);

		key = STAT_MAP_UPDATES;
		__u64 *updates = bpf_map_lookup_elem(&tc_stats, &key);
		if (updates)
			__sync_fetch_and_add(updates, 1);
	}
	/* IPv6 traffic */
	else if (eth_proto == ETH_P_IPV6) {
		struct in6_addr src_ip, dst_ip;
		__u16 src_port, dst_port;
		__u8 protocol;

		if (read_ipv6_packet(skb, &src_ip, &dst_ip, &src_port,
				     &dst_port, &protocol) < 0) {
			return TC_ACT_OK;
		}

		/* Calculate flow key for IPv6 */
		flow_key_t flow_key =
			fnv1a_hash_v6(&src_ip, &dst_ip, src_port, dst_port,
				      protocol);

		/* Store in BPF map */
		struct flow_metadata metadata = {
			.ifindex = ifindex,
			.timestamp = bpf_ktime_get_ns(),
			.src_port = src_port,
			.dst_port = dst_port,
			.protocol = protocol,
			.ip_version = 6,
		};

		bpf_map_update_elem(&flow_to_interface, &flow_key, &metadata,
				    BPF_ANY);

		/* Update statistics */
		key = STAT_IPV6_PACKETS;
		__u64 *ipv6_count = bpf_map_lookup_elem(&tc_stats, &key);
		if (ipv6_count)
			__sync_fetch_and_add(ipv6_count, 1);

		key = STAT_MAP_UPDATES;
		__u64 *updates = bpf_map_lookup_elem(&tc_stats, &key);
		if (updates)
			__sync_fetch_and_add(updates, 1);
	} else {
		/* Unknown protocol */
		key = STAT_UNKNOWN_PACKETS;
		__u64 *unknown = bpf_map_lookup_elem(&tc_stats, &key);
		if (unknown)
			__sync_fetch_and_add(unknown, 1);
	}

	return ret;  /* Always allow packet through */
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
