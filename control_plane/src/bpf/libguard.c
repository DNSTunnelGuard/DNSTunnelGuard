

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <string.h>
#include <unistd.h>


/* Dynamic library to be used by the control plane to interact with BPF maps 
 * This seemed easier to reduce the ammount of python ctypes use 
 *
 *
 *
 */ 

#define MAX_QNAME_LEN 64

/* Get the file descriptor given a BPF map name
 *
 */ 
int get_map_fd(const char* name)
{
    int   map_fd = -1;
    __u32 id     = 0;
    while (bpf_map_get_next_id(id, &id) == 0)
    {
        struct bpf_map_info info     = {};
        __u32               info_len = sizeof(info);
        int                 fd;

        fd = bpf_map_get_fd_by_id(id);
        if (fd < 0)
            continue;

        if (bpf_obj_get_info_by_fd(fd, &info, &info_len) == 0)
        {
            if (strcmp(info.name, name) == 0)
            {
                map_fd = fd;
                break;
            }
        }
        close(fd);
    }
    return map_fd;
}

/* Update the blocked IP address map given its file descriptor 
 * with an IP address to block 
 */
int map_ip(int fd, uint32_t ip_addr)
{
    int blocked = 1;
    return bpf_map_update_elem(fd, &ip_addr, &blocked, BPF_ANY);
}

/* Update the blocked IP address map given its file descriptor 
 * with an IP address to unblock 
 */
int unmap_ip(int fd, uint32_t ip_addr) { return bpf_map_delete_elem(fd, &ip_addr); }

/* Update the blocked domain map given its file descriptor 
 * with an domain to block 
 */
int map_domain(int fd, char* domain_name)
{
    char key[MAX_QNAME_LEN] = {0};
    strncpy(key, domain_name, MAX_QNAME_LEN);
    uint8_t blocked = 1;

    return bpf_map_update_elem(fd, key, &blocked, BPF_ANY);
}

/* Update the blocked domain map given its file descriptor 
 * with an domain to unblock 
 */
int unmap_domain(int fd, char* domain)
{
    char key[MAX_QNAME_LEN] = {0};
    strncpy(key, domain, MAX_QNAME_LEN);
    return bpf_map_delete_elem(fd, key);
}

/* Ring buffer state for query events */  
struct ring_buffer* query_rb = NULL; 
int (*rb_callback)(void* ctx, void* data, size_t size) = NULL;

/* Create the ring buffer for query events given the ringbuffers file descriptor 
 * and a callback on query receivel
 */
int create_ringbuffer(int fd, int (*callback)(void* ctx, void* data, size_t size))
{
    rb_callback = callback; 
    query_rb = ring_buffer__new(fd, callback, NULL, 0);
    if (query_rb == NULL)
        return -1; 
    return 0; 
}

/* If a query exists, call the stored callback on the query 
 * Wait a specified timeout before unblocking. Pass in a large number for long blocking 
 */
void poll_ringbuffer(int timeout)
{
    ring_buffer__poll(query_rb, timeout);
}



