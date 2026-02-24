
#include "guards.h"

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, uint32_t);  // IP address 
    __type(value, uint8_t); // is blocked 
    __uint(max_entries, MAX_BLOCKED_LENGTH);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blkd_ip_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, char[MAX_QNAME_LEN]); // Domain Name
    __type(value, uint8_t);           // is blocked
    __uint(max_entries, MAX_BLOCKED_LENGTH);
    __uint(pinning, LIBBPF_PIN_BY_NAME);

} blkd_domain_map SEC(".maps");


/* Tunnel guard for incoming traffic (ingress) to the DNS resolver
 *
 * Drops packets under the following conditions: 
 * - the packet is TCP 
 * - the packet is IPv6
 * - the requesters IP address is blocked
 * - the domain name contains a blocked sub domain 
 * - the query is too long 
 * - the query type is disallowed 
 *
 * if the packet is coming from a client and is allowed to pass, 
 * the source IP address of the client will be mapped to a domain name. 
 * This is so the egress guard can push both the DNS query and the source IP 
 * address to the control plane. 
 *
 * The mapping will be removed by the egress guard after it has finished processing.  
 *
 * Allowed qtypes include: 
 *  A
 *  AAAA
 *  CNAME
 *  MX
 *  NS
 *  SOA
 *  PTR
 *
 */
SEC("cgroup_skb/ingress")
int tunnel_guard_ingress(struct __sk_buff* skb)
{

    void* data_end = (void*)(long)skb->data_end;
    void* data     = (void*)(long)skb->data;

    /* No ipv6, too complicated to parse rn */
    if (skb->protocol == bpf_htons(ETH_P_IPV6))
        return DROP;

    if (data + sizeof(struct iphdr) >= data_end)
        return PASS;

    struct iphdr* ip_header = data;

    /* Drop query if the packet comes from a blocked requesters IP */ 
    if (bpf_map_lookup_elem(&blkd_ip_map, &ip_header->saddr))
        return DROP; 

    void*    transport_header = (void*)ip_header + ip_header->ihl * 4;
    void*    dns_header;
    uint16_t dst_port;

    if (ip_header->protocol == IPPROTO_UDP)
    {
        struct udphdr* udp_header = transport_header;
        if ((void*)udp_header + sizeof(struct udphdr) >= data_end)
            return PASS;
        dns_header = (void*)udp_header + sizeof(struct udphdr);
        dst_port   = udp_header->dest; 
    }
    else if (ip_header->protocol == IPPROTO_TCP)
    {
        return DROP; // I dont want to deal with tcp rn 
    }
    else
    {
        return PASS;
    }

    if (dns_header >= data_end)
        return PASS;

    /* Only look at traffic coming from user queries */ 
    if (bpf_ntohs(dst_port) != DNS_PORT)
        return PASS;

    char* qname = dns_header + DNS_HDR_LEN;

    /* Determine the length and drop if too long*/
    int len;
    for (len = 0; len < MAX_QNAME_LEN; len++)
    {
        if ((void*)qname + len >= data_end)
            return DROP;

        if (qname[len] == '\0')
            break;
    }

    if (len > MAX_QNAME_LEN)
        return DROP;


    char full_qname[MAX_QNAME_LEN] = {0};

    if (bpf_probe_read_kernel(full_qname, len, qname) < 0)
        return DROP;

    /*
     * Check each subdomain and drop if it is blocked
     * EX: JFDSL.attacker.com
     * Checks JFDSL.attacker.com
     * Then checks attacker.com
     * Then .com
     * Checks in wire format, not presentation
     */

    int remaining_label_chars = 0;
    for (int i = 0; i < len; i++)
    {
        if (remaining_label_chars == 0)
        {
            char sub_domain[MAX_QNAME_LEN] = {0};

            int copy_len = len - i + 1;

            if (bpf_probe_read_kernel(sub_domain, copy_len, qname + i) < 0)
                return DROP;

            if (bpf_map_lookup_elem(&blkd_domain_map, sub_domain))
                return DROP;

            remaining_label_chars = full_qname[i];
        }
        else
        {
            remaining_label_chars--;
        }
    }


    uint16_t* qtype_ptr = (uint16_t*)(qname + len + 1);

    if ((char*)(qtype_ptr + 1) > (char*)data_end)
        return DROP;

    uint16_t qtype = bpf_ntohs(*qtype_ptr);


    switch (qtype)
    {
    case QTYPE_A:
    case QTYPE_AAAA:
    case QTYPE_CNAME:
    case QTYPE_MX:
    case QTYPE_NS:
    case QTYPE_SOA:
    case QTYPE_PTR:
    {
        /* Map the IP to the query name */ 
        bpf_map_update_elem(&query_to_ip, full_qname, &ip_header->saddr, BPF_ANY);
        return PASS;
    }

    default:
        return DROP;
    }

    
    return PASS; 
}

char _license[] SEC("license") = "GPL";





