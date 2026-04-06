// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Forwarded Flow Tracker - TCX ingress/egress classifier
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"

char LICENSE[] SEC("license") = "GPL";

struct forward_event_t {
	__u64 ts;
	__u32 pid;
	__u32 packet_len;
	__u32 ifindex;
	__u16 src_port;
	__u16 dst_port;
	__u8 family;   // 4 or 6
	__u8 protocol; // TCP=6, UDP=17, ICMP=1, ICMPv6=58
	__u8 hook;     // 1 ingress, 2 egress
	__u8 reserved;
	__u32 src_ip;
	__u32 dst_ip;
	__u8 src_ip6[16];
	__u8 dst_ip6[16];
	char ifname[16];
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// Parse IPv4 packet from skb data pointers.
static __always_inline int read_ipv4_packet(struct __sk_buff *skb, __u32 *src_ip,
					    __u32 *dst_ip, __u16 *src_port,
					    __u16 *dst_port, __u8 *protocol) {
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return -1;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return -1;

	*src_ip = ip->saddr;
	*dst_ip = ip->daddr;
	*protocol = ip->protocol;
	*src_port = 0;
	*dst_port = 0;

	__u32 ip_hdr_len = ip->ihl * 4;
	if (ip_hdr_len < sizeof(*ip))
		return 0;

	if (*protocol == IPPROTO_TCP) {
		void *tcp_ptr = (void *)ip + ip_hdr_len;
		if (tcp_ptr + 4 > data_end)
			return 0;
		__be16 ports[2] = {};
		if (bpf_probe_read_kernel(&ports, sizeof(ports), tcp_ptr) < 0)
			return 0;
		*src_port = bpf_ntohs(ports[0]);
		*dst_port = bpf_ntohs(ports[1]);
	} else if (*protocol == IPPROTO_UDP) {
		void *udp_ptr = (void *)ip + ip_hdr_len;
		if (udp_ptr + 4 > data_end)
			return 0;
		__be16 ports[2] = {};
		if (bpf_probe_read_kernel(&ports, sizeof(ports), udp_ptr) < 0)
			return 0;
		*src_port = bpf_ntohs(ports[0]);
		*dst_port = bpf_ntohs(ports[1]);
	}

	return 0;
}

// Parse IPv6 packet from skb data pointers.
static __always_inline int read_ipv6_packet(struct __sk_buff *skb, struct in6_addr *src_ip,
					    struct in6_addr *dst_ip, __u16 *src_port,
					    __u16 *dst_port, __u8 *protocol) {
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return -1;

	struct ipv6hdr *ip6 = (void *)(eth + 1);
	if ((void *)(ip6 + 1) > data_end)
		return -1;

	*src_ip = ip6->saddr;
	*dst_ip = ip6->daddr;
	*protocol = ip6->nexthdr;
	*src_port = 0;
	*dst_port = 0;

	if (*protocol == IPPROTO_TCP || *protocol == IPPROTO_UDP) {
		void *l4_ptr = (void *)(ip6 + 1);
		if (l4_ptr + 4 > data_end)
			return 0;
		__be16 ports[2] = {};
		if (bpf_probe_read_kernel(&ports, sizeof(ports), l4_ptr) < 0)
			return 0;
		*src_port = bpf_ntohs(ports[0]);
		*dst_port = bpf_ntohs(ports[1]);
	}

	return 0;
}

static __always_inline int emit_flow_event(struct __sk_buff *skb, __u8 hook) {
	struct forward_event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return TC_ACT_OK;

	__builtin_memset(e, 0, sizeof(*e));
	e->ts = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->packet_len = skb->len;
	e->hook = hook;
	e->ifindex = (hook == 1) ? skb->ingress_ifindex : skb->ifindex;

	__u16 eth_proto = bpf_ntohs(skb->protocol);
	if (eth_proto == ETH_P_IP) {
		__u8 proto = 0;
		e->family = 4;
		if (read_ipv4_packet(skb, &e->src_ip, &e->dst_ip, &e->src_port,
				     &e->dst_port, &proto) == 0) {
			e->protocol = proto;
		}
	} else if (eth_proto == ETH_P_IPV6) {
		struct in6_addr src = {};
		struct in6_addr dst = {};
		__u8 proto = 0;
		e->family = 6;
		if (read_ipv6_packet(skb, &src, &dst, &e->src_port, &e->dst_port,
				     &proto) == 0) {
			e->protocol = proto;
#pragma unroll
			for (int i = 0; i < 16; i++) {
				e->src_ip6[i] = src.in6_u.u6_addr8[i];
				e->dst_ip6[i] = dst.in6_u.u6_addr8[i];
			}
		}
	}

	bpf_ringbuf_submit(e, 0);
	return TC_ACT_OK;
}

SEC("tc")
int tc_forward_ingress(struct __sk_buff *skb) {
	return emit_flow_event(skb, 1);
}

SEC("tc")
int tc_forward_egress(struct __sk_buff *skb) {
	return emit_flow_event(skb, 2);
}
