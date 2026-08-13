#include "../include/sniffer.h"

void packet_callback(u_char *user_args, const struct pcap_pkthdr *cap_header, const u_char *packet_body) {
    (void)user_args;
    /*printf("[%d] Packet captured! | Captured Length: %d bytes | Total Length: %d bytes\n", 
            packet_count++, cap_header->caplen, cap_header->len);*/
    parse_packet(packet_body, cap_header->len);
}

int start_sniffer(const char *device_name) {
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    printf("Starting C Packet Sniffer on interface '%s'...\n", device_name);

    handle = pcap_open_live(device_name, 65536, 1, 1000, error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "Error opening device %s: %s\n", device_name, error_buffer);
        return -1;
    }

    printf("Sniffer is actively listening... Press Ctrl+C to stop.\n\n");
    pcap_loop(handle, -1, packet_callback, NULL);

    pcap_close(handle);
    return 0;
}