#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <netinet/ip.h>          
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/ip.h>

#include <ctype.h>

#define BUFFER_SIZE 65536

//Make odd number to show. 
int showpayload = 3;

struct tcphdr {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;

    uint16_t res1:4;    // 4 bits reserved
    uint16_t doff:4;    // Data Offset (header length) in 4-byte words
    uint16_t fin:1;     // FIN flag
    uint16_t syn:1;     // SYN flag
    uint16_t rst:1;     // RST flag
    uint16_t psh:1;     // PSH flag
    uint16_t ack:1;     // ACK flag
    uint16_t urg:1;     // URG flag
    uint16_t ece:1;     // ECE flag (ECN-Echo)
    uint16_t cwr:1;     // CWR flag (Congestion Window Reduced)

    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

struct prmpckt {
    uint16_t preamble:4;        // Sync bytes (4 bits)
    uint16_t hdr:8;             // Header (8 bits)
    uint16_t srcaddr:6;         // Source Address (6 bits)
    uint16_t destaddr:6;        // Destination Address (6 bits)
    uint16_t timestamp:8;       // Timestamp (8 bits)
    uint16_t seq:4;             // Sequence Number (4 bits)
    uint16_t measurement_data:8; // Measurement data (e.g., signal strength, SNR, 8 bits)
    uint16_t checksum:8;        // Checksum (8 bits)
    uint16_t payload_length:8;  // Payload length (8 bits)
    uint8_t payload[0];         // Flexible array member for payload (optional)
};

struct udphdr {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};


// Function to check if a byte is printable
int is_printable(unsigned char c) {
    return (c >= 32 && c <= 126);  // Printable ASCII characters range from 32 to 126
}

// Function to print the packet as ASCII, ignoring non-printable bytes
void print_packet_ascii(char *buffer, ssize_t received) {
    printf("\nASCII: \n");
    for (size_t i = 0; i < received; i++) {
        if (is_printable((unsigned char)buffer[i])) {
            printf("%c", buffer[i]);  // Print printable characters
        } else {
            printf(".");  // Represent non-printable characters as dots
        }
    }
    printf("\n========================================================\n");
}

void print_eth_header(unsigned char *buffer, int size) { 
    struct ethhdr *eth = (struct ethhdr *)buffer;

    printf("\n==================== ETHERNET FRAME ====================\n");

    printf("   |-Destination MAC  : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
           eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], 
           eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);

    printf("   |-Source MAC       : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
           eth->h_source[0], eth->h_source[1], eth->h_source[2], 
           eth->h_source[3], eth->h_source[4], eth->h_source[5]);

    printf("   |-Protocol Type    : 0x%04X (%s)\n", 
           ntohs(eth->h_proto),
           (ntohs(eth->h_proto) == 0x0800) ? "IPv4" :
           (ntohs(eth->h_proto) == 0x0806) ? "ARP" :
           (ntohs(eth->h_proto) == 0x86DD) ? "IPv6" : "Unknown");

    // Print raw payload data
    int payload_size = size - sizeof(struct ethhdr);
    unsigned char *payload = buffer + sizeof(struct ethhdr);

    printf("\n==================== PAYLOAD DATA ====================\n");
    for (int i = 0; i < payload_size; i++) {
        if (i % 16 == 0) printf("\n");  // New line every 16 bytes
        printf("%.2X ", payload[i]);
    }
    printf("\n======================================================\n");
}

void print_ip_header(unsigned char *buffer, int size) { 
    struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    printf("\nIP HEADER:\n");
    printf("IP Version: %d\n", ip_header->version);
    printf("IHL: %d\n", ip_header->ihl);
    printf("Type of Service: 0x%x\n", ip_header->tos);
    printf("Total Length: %d\n", ntohs(ip_header->tot_len));
    printf("Identification: %d\n", ntohs(ip_header->id));
    printf("TTL: %d\n", ip_header->ttl);
    printf("Protocol: %d\n", ip_header->protocol);
    printf("Checksum: 0x%x\n", ntohs(ip_header->check));
    printf("Source IP: %s\n", inet_ntoa(*(struct in_addr *)&ip_header->saddr));
    printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&ip_header->daddr));
    return;
}

void print_tcp_packet(unsigned char *buffer, int size) {
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + ip->ihl * 4);

    printf("\n==================== TCP PACKET ====================\n");

    // Print IP Header details
    print_ip_header(buffer, size);

    printf("\nTCP HEADER:\n");
    printf("Source Port      : %u\n", ntohs(tcp->source));
    printf("Destination Port : %u\n", ntohs(tcp->dest));
    printf("Sequence Number  : %u\n", ntohl(tcp->seq));
    printf("Acknowledgement  : %u\n", ntohl(tcp->ack_seq));
    printf("Data Offset      : %d (bytes)\n", tcp->doff * 4);
    
    // Print TCP Flags
    printf("Flags:\n");
    printf("   |-URG: %d\n", (tcp->urg ? 1 : 0));
    printf("   |-ACK: %d\n", (tcp->ack ? 1 : 0));
    printf("   |-PSH: %d\n", (tcp->psh ? 1 : 0));
    printf("   |-RST: %d\n", (tcp->rst ? 1 : 0));
    printf("   |-SYN: %d\n", (tcp->syn ? 1 : 0));
    printf("   |-FIN: %d\n", (tcp->fin ? 1 : 0));

    printf("Window Size      : %u\n", ntohs(tcp->window));
    printf("Checksum         : 0x%x\n", ntohs(tcp->check));
    printf("Urgent Pointer   : %u\n", ntohs(tcp->urg_ptr));

    // Print raw payload data
    int header_size = sizeof(struct ethhdr) + ip->ihl * 4 + tcp->doff * 4;
    int payload_size = size - header_size;
    unsigned char *payload = buffer + header_size;
    printf("\nPAYLOAD DATA (%d bytes):\n", payload_size);
    if (showpayload & 1) {
        if (payload_size > 0) {
            for (int i = 0; i < payload_size; i += 16) {
                printf("\n%04X  ", i); // Print offset in hex
    
                // Print hex values
                for (int j = 0; j < 16; j++) {
                    if (i + j < payload_size)
                        printf("%.2X ", payload[i + j]);
                    else
                        printf("   ");  // Padding for alignment
                }
    
                printf("  "); // Separator between hex and ASCII
    
                // Print ASCII characters
                for (int j = 0; j < 16; j++) {
                    if (i + j < payload_size) {
                        unsigned char c = payload[i + j];
                        printf("%c", isprint(c) ? c : '.');  // Print only printable characters
                    }
                }
            }
        } else {
            printf("No payload data available.\n");
        }
    }
    printf("\n======================================================\n");
}

void print_icmp_packet(unsigned char *buffer, int size) {
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    struct icmphdr *icmp = (struct icmphdr *)(buffer + sizeof(struct ethhdr) + ip->ihl * 4);

    printf("\nICMP Packet\n");
    print_ip_header(buffer, size);
    printf("\n   |-Type : %d\n", icmp->type);
    printf("   |-Code : %d\n", icmp->code);
    printf("   |-Checksum : %d\n", ntohs(icmp->checksum));
}

void print_udp_packet(unsigned char *buffer, int size) {
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    struct udphdr *udp = (struct udphdr *)(buffer + sizeof(struct ethhdr) + ip->ihl * 4);

    printf("\nUDP Packet\n");
    print_ip_header(buffer, size);
    printf("\n   |-Source Port      : %u\n", ntohs(udp->source));
    printf("   |-Destination Port : %u\n", ntohs(udp->dest));
    printf("   |-Length           : %u\n", ntohs(udp->len));
}

void print_prm_packet(unsigned char *buffer, int size) {
    struct prmpckt *prm = (struct prmpckt *)buffer;  // Parse the PRM packet into our struct

    printf("\n==================== PRM PACKET ====================\n");

    // Print the individual fields of the PRM packet
    printf("Preamble        : 0x%.1X\n", prm->preamble);
    printf("Header          : 0x%.2X\n", prm->hdr);
    printf("Source Address  : 0x%.X\n", prm->srcaddr);
    printf("Destination Addr: 0x%.X\n", prm->destaddr);
    printf("Timestamp       : 0x%.2X\n", prm->timestamp);
    printf("Sequence Number : 0x%.1X\n", prm->seq);
    printf("Measurement Data: 0x%.2X\n", prm->measurement_data);
    printf("Checksum        : 0x%.2X\n", prm->checksum);
    printf("Payload Length  : %u\n", prm->payload_length);

    // Print Payload data if necessary
    int header_size = sizeof(struct prmpckt);
    int payload_size = size - header_size;
    unsigned char *payload = buffer + header_size;

    printf("\nPAYLOAD DATA (%d bytes):\n", payload_size);
    for (int i = 0; i < payload_size; i++) {
        if (i % 16 == 0) printf("\n");  // New line every 16 bytes
        printf("%.2X ", payload[i]);
    }
    printf("\n");
    print_packet_ascii((char *)payload,payload_size);
}


void process_packet(unsigned char *buffer, int size) {
    struct iphdr *ip_header = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    printf("\nRaw IP Header Bytes:\n");
    for (int i = 0; i < sizeof(struct iphdr); i++) {
        printf("%.2X ", buffer[sizeof(struct ethhdr) + i]);
    }
    printf("\n");
    
    switch (ip_header->protocol) {
        case IPPROTO_ETHERNET:
            print_eth_header(buffer,size);
            break;
        case IPPROTO_TCP:
            print_tcp_packet(buffer, size);
            break;
        case IPPROTO_UDP:
            print_udp_packet(buffer, size);
            break;
        case IPPROTO_ICMP:
            print_icmp_packet(buffer, size);
            break;
        case 21:
            print_prm_packet(buffer, size);
            break;
        default:
            print_ip_header(buffer, size);
            break;
    }
}

int main() {
    int sock_raw;
    struct sockaddr saddr;
    socklen_t saddr_len = sizeof(saddr);

    unsigned char *buffer = (unsigned char *)malloc(BUFFER_SIZE);
    if (buffer == NULL) {
        perror("Failed to allocate memory");
        return 1;
    }

    sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        perror("Socket Error");
        free(buffer);
        return 1;
    }

    printf("Starting packet sniffer...\n");

    while (1) {
        int data_size = recvfrom(sock_raw, buffer, BUFFER_SIZE, 0, &saddr, &saddr_len);
        if (data_size < 0) {
            perror("Failed to receive packets");
            break;
        }
        process_packet(buffer, data_size);
    }

    close(sock_raw);
    free(buffer);
    return 0;
}
