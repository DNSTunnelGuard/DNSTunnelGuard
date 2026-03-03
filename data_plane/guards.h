
#pragma once 

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define bpf_htonl(x) __builtin_bswap32(x)
#define bpf_ntohl(x) __builtin_bswap32(x)
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define MAX_QUERY_LEN 508

#define MAX_BLOCKED_LENGTH 10000
#define DROP 0
#define PASS 1

// DNS
#define DNS_HDR_LEN 12
#define MAX_QNAME_LEN 64
#define MAX_LABEL_SIZE 20
#define DNS_PORT 53

#define QTYPE_A 1
#define QTYPE_AAAA 28
#define QTYPE_NS 2
#define QTYPE_SOA 6
#define QTYPE_MX 15
#define QTYPE_PTR 12
#define QTYPE_CNAME 5


struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, char[MAX_QNAME_LEN]);    // Domain Name
    __type(value, uint32_t);             // Associated IP address
    __uint(max_entries, MAX_BLOCKED_LENGTH);
    __uint(pinning, LIBBPF_PIN_BY_NAME);

} query_to_ip SEC(".maps");
