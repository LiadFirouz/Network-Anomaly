#include "../include/sniffer.h"

int main(int argc, char *argv[]) {
    // Default network device in Linux Docker container
    const char *device = "any";

    if (argc > 1) {
        device = argv[1];
    }

    if (start_sniffer(device) != 0) {
        fprintf(stderr, "Failed to run packet sniffer.\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}