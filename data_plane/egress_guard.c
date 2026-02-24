

#include "guards.h"


/* Buffer to write DNS queries for further inspection in user space */
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} query_events SEC(".maps");

struct query_event
{
    uint32_t ip_address; 
    char     query_data[MAX_QUERY_LEN];
};

/* Tunnel guard for outgoing traffic (egress) from the DNS resolver
 * 
 * Finds the associated IP address with the query and removes the mapping 
 *
 * If the query is outgoing to another DNS server, the query and client
 * IP address is pushed to a shared ringbuffer with the control plane and allowed to pass. 
 *
 * The egress guard should not be relied to filer queries, as that is left
 * to the ingress guard. Queries should be passed through the egress guard, 
 * only being blocked after the control plane as determined a query suspicious, updating 
 * the blocked maps the ingress guard uses. 
 */

SEC("cgroup_skb/egress")
int tunnel_guard_egress(struct __sk_buff* skb)
{


    void* data_end = (void*)(long)skb->data_end;
    void* data     = (void*)(long)skb->data;

    /* ------------------------------ IP ---------------------------- */

    /* No ipv6, too complicated to parse rn */

    if (skb->protocol == bpf_htons(ETH_P_IPV6))
        return DROP;

    if (data + sizeof(struct iphdr) >= data_end)
        return PASS;

    struct iphdr* ip_header = data;

    /* ---------------------------- Transport ---------------------------- */


    uint16_t dst_port;
    uint16_t src_port; 
    void*    dns_header;
    void*    transport_header = (void*)ip_header + ip_header->ihl * 4;

    if (ip_header->protocol == IPPROTO_UDP)
    {
        struct udphdr* udp_header = transport_header;
        if ((void*)udp_header + sizeof(struct udphdr) >= data_end)
            return PASS;
        dst_port   = bpf_ntohs(udp_header->dest);
        src_port   = bpf_ntohs(udp_header->source); 
        dns_header = (void*)udp_header + sizeof(struct udphdr);
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

    /* ----------------------------  DNS ---------------------------- */

    /*
     * This is egress traffic, we only need to analyze queries going to DNS servers,
     * not traffic being sent back to the client
     */
    if (dst_port != DNS_PORT)
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

    /* Get the requsters IP address with this query */

    char full_qname[MAX_QNAME_LEN] = {0};

    if (bpf_probe_read_kernel(full_qname, len, qname) < 0)
        return DROP;

    uint32_t* ip_addr_p = bpf_map_lookup_elem(&query_to_ip, full_qname);

    /* There should be a mapping when query is leaving resolver to DNS server. */ 

    if (!ip_addr_p)
        return DROP; 


    uint32_t ip_addr = bpf_htonl(*ip_addr_p);
    bpf_map_delete_elem(&query_to_ip, full_qname);

    struct query_event* event = bpf_ringbuf_reserve(&query_events, sizeof(struct query_event), 0); 

    if (!event)
        return DROP; 

    event->ip_address = bpf_ntohl(ip_addr); 
    for (int i = 0; i < MAX_QUERY_LEN; i++)
    {
        if (dns_header + i >= data_end)
            break;

        event->query_data[i] = ((char*)dns_header)[i];
    }
    bpf_ringbuf_submit(event, 0);

    return PASS;
}

char _license[] SEC("license") = "GPL";
