#include <stdio.h>
#include <stdlib.h>

void print_file(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        printf("Error: Could not open file %s\n", filename);
        return;
    }

    char buffer[256]; // Buffer overflow vulnerability
    while (fgets(buffer, sizeof(buffer) + 400, file) != NULL) {
        // Intentional format string vulnerability
        printf(buffer);
    }

    fclose(file);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    print_file(argv[1]);
    return 0;
}
