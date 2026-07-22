#include "../include/protocol_parser.h"

void parse_packet(const u_char *packet_body, uint32_t length) {
    // 1. Skip Ethernet header (14 bytes) to reach the IP header
    struct ip *ip_hdr = (struct ip *)(packet_body + sizeof(struct ether_header));

    PacketFeatures features;
    features.packet_length = length;
    features.protocol = ip_hdr->ip_p;

    // Convert IP binary addresses to human-readable strings
    inet_ntop(AF_INET, &(ip_hdr->ip_src), features.src_ip, sizeof(features.src_ip));
    inet_ntop(AF_INET, &(ip_hdr->ip_dst), features.dst_ip, sizeof(features.dst_ip));

    features.src_port = 0;
    features.dst_port = 0;

    // Calculate IP header length (ip_hl gives size in 32-bit words)
    int ip_header_len = ip_hdr->ip_hl * 4;

    // 2. Inspect Transport Layer Protocol (TCP / UDP)
    if (ip_hdr->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp_hdr = (struct tcphdr *)(packet_body + sizeof(struct ether_header) + ip_header_len);
        
        // Portable handling for TCP ports across macOS and Linux
#if defined(__FAVOR_BSD) || defined(__APPLE__)
        features.src_port = ntohs(tcp_hdr->th_sport);
        features.dst_port = ntohs(tcp_hdr->th_dport);
#else
        features.src_port = ntohs(tcp_hdr->source);
        features.dst_port = ntohs(tcp_hdr->dest);
#endif

        printf("[TCP] %s:%d --> %s:%d | Length: %u bytes\n",
               features.src_ip, features.src_port,
               features.dst_ip, features.dst_port,
               features.packet_length);

    } else if (ip_hdr->ip_p == IPPROTO_UDP) {
        struct udphdr *udp_hdr = (struct udphdr *)(packet_body + sizeof(struct ether_header) + ip_header_len);
        
        // Portable handling for UDP ports across macOS and Linux
#if defined(__FAVOR_BSD) || defined(__APPLE__)
        features.src_port = ntohs(udp_hdr->uh_sport);
        features.dst_port = ntohs(udp_hdr->uh_dport);
#else
        features.src_port = ntohs(udp_hdr->source);
        features.dst_port = ntohs(udp_hdr->dest);
#endif

        printf("[UDP] %s:%d --> %s:%d | Length: %u bytes\n",
               features.src_ip, features.src_port,
               features.dst_ip, features.dst_port,
               features.packet_length);
    } else {
        printf("[OTHER Protocol %d] %s --> %s | Length: %u bytes\n",
               features.protocol, features.src_ip, features.dst_ip, features.packet_length);
    }
}