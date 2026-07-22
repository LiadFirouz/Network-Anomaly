#ifndef SNIFFER_H
#define SNIFFER_H

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>

#include "protocol_parser.h"

// Function Declarations
int start_sniffer(const char *device_name);
void packet_callback(u_char *user_args, const struct pcap_pkthdr *cap_header, const u_char *packet_body);

#endif // SNIFFER_H