#ifndef PROTOCOL_PARSER_H
#define PROTOCOL_PARSER_H

// Define feature test macros to ensure BSD/Linux compatibility for network headers
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif

#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

// Struct to hold extracted features for the ML model
typedef struct {
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint32_t packet_length;
} PacketFeatures;

// Function declarations
void parse_packet(const u_char *packet_body, uint32_t length);

#endif // PROTOCOL_PARSER_H