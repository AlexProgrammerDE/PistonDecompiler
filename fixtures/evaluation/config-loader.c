#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct settings { unsigned int port; int verbose; };

static int parse_entry(char *line, struct settings *settings) {
    char *separator = strchr(line, '=');
    if (separator == NULL) return 0;
    *separator++ = '\0';
    if (strcmp(line, "port") == 0) {
        char *end;
        unsigned long port = strtoul(separator, &end, 10);
        if (end == separator || (*end != '\n' && *end != '\0') || port > 65535) return -1;
        settings->port = (unsigned int)port;
        return 1;
    }
    if (strcmp(line, "verbose") == 0) {
        settings->verbose = strcmp(separator, "true\n") == 0 || strcmp(separator, "true") == 0;
        return 1;
    }
    return 0;
}

static int load_settings(const char *path, struct settings *settings) {
    FILE *file = fopen(path, "r");
    if (file == NULL) return -1;
    char line[256];
    int count = 0;
    while (fgets(line, sizeof(line), file) != NULL) {
        int parsed = parse_entry(line, settings);
        if (parsed < 0) { fclose(file); return -2; }
        count += parsed;
    }
    fclose(file);
    return count;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    struct settings settings = { 8080, 0 };
    int count = load_settings(argv[1], &settings);
    if (count < 0) return 1;
    printf("port=%u verbose=%d entries=%d\n", settings.port, settings.verbose, count);
    return 0;
}
