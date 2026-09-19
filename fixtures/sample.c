#include <stdint.h>
#include <stdio.h>
#include <string.h>

uint32_t checksum(const unsigned char *data, size_t length) {
    uint32_t value = 2166136261u;
    for (size_t i = 0; i < length; i++) value = (value ^ data[i]) * 16777619u;
    return value;
}

int validate_packet(const unsigned char *data, size_t length) {
    if (length < 8 || memcmp(data, "PSTN", 4) != 0) return 0;
    return checksum(data + 4, length - 4) != 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { puts("Usage: sample PACKET"); return 1; }
    size_t length = strlen(argv[1]);
    printf("packet valid: %d\n", validate_packet((unsigned char *)argv[1], length));
    return 0;
}
