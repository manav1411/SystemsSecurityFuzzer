#include <stdio.h>
#include <stdlib.h>

#define BUFFER_SIZE 102400

// read and print chars from a file
void read_and_print_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        printf("Error: Could not open file '%s'\n", filename);
        return;
    }

    char buffer[BUFFER_SIZE]; // Fixed-size buffer (vuln)

    // no proper bounds checking
    size_t bytes_read = fread(buffer, 1, BUFFER_SIZE * 2, file); // Reading more than BUFFER_SIZE
    if (bytes_read > BUFFER_SIZE) {
        printf("Potential overflow: Read %zu bytes into a %d-byte buffer!\n", bytes_read, BUFFER_SIZE);
    }

    fwrite(buffer, 1, bytes_read, stdout); // Attempt to output the read bytes
    printf("\nBuffer: %s\n", buffer);      // Print buffer contents (unsafe if overflowed)

    fclose(file);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: ./pdf_test_buffer <text-file>\n");
        return 1;
    }

    const char *filename = argv[1];
    read_and_print_file(filename);

    return 0;
}
