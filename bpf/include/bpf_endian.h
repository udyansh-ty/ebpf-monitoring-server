#ifndef __BPF_ENDIAN_H
#define __BPF_ENDIAN_H

#include "vmlinux.h"

// ANCHOR: Endian Helpers - Build fix - Feb 25, 2026
// Provide minimal endian helpers used by local BPF programs.

#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#define bpf_ntohl(x) __builtin_bswap32(x)
#define bpf_htonll(x) __builtin_bswap64(x)
#define bpf_ntohll(x) __builtin_bswap64(x)

#endif /* __BPF_ENDIAN_H */
