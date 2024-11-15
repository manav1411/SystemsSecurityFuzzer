#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SECTION_NAME_SIZE 32

typedef struct {
    char section_name[MAX_SECTION_NAME_SIZE];
    int section_size;
} ElfSection;

void parse_elf(FILE *file) {
    ElfSection section;
    char input_buffer[64];  // Vulnerable buffer size

    printf("Enter section name to print details: ");
    fgets(input_buffer, 128, stdin);  // Potential buffer overflow

    while (fread(&section, sizeof(ElfSection), 1, file)) {
        // Vulnerable string comparison allowing potential buffer overflow
        if (strncmp(section.section_name, input_buffer,
                    strlen(input_buffer) - 1) == 0) {
            printf("Section: %s\n", section.section_name);
            printf("Size: %d bytes\n", section.section_size);
            return;
        }
    }

    printf("Section not found.\n");
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <ELF file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    FILE *file = fopen(argv[1], "rb");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    parse_elf(file);

    fclose(file);
    return 0;
}
