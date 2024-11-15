#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>

#define MAX_BUF_SIZE 256  // Arbitrary buffer size that can be overflowed

// Vulnerable function that parses the ELF header
void parse_elf(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open ELF file");
        exit(1);
    }

    // Read the ELF header
    Elf64_Ehdr elf_header;
    if (fread(&elf_header, sizeof(Elf64_Ehdr), 1, file) != 1) {
        perror("Failed to read ELF header");
        fclose(file);
        exit(1);
    }

    // Print some ELF header information (no validation here)
    printf("ELF Magic: %c%c%c%c\n", elf_header.e_ident[0],
           elf_header.e_ident[1], elf_header.e_ident[2], elf_header.e_ident[3]);
    printf("ELF Type: %u\n", elf_header.e_type);
    printf("ELF Entry point: 0x%lx\n", elf_header.e_entry);

    // Buffer to hold some ELF section data
    char buffer[MAX_BUF_SIZE];

    // Vulnerability: no bounds checking on reading ELF section name
    fseek(file, elf_header.e_shoff,
          SEEK_SET);  // Seek to the section header table
    if (fread(buffer, 1, elf_header.e_shnum * sizeof(Elf64_Shdr), file) < 0) {
        perror("Failed to read section headers");
        fclose(file);
        exit(1);
    }

    // Dangerous: no bounds checking when copying section names (potential
    // overflow)
    for (int i = 0; i < elf_header.e_shnum; i++) {
        Elf64_Shdr section_header;
        memcpy(&section_header, buffer + i * sizeof(Elf64_Shdr),
               sizeof(Elf64_Shdr));

        fseek(file, section_header.sh_name, SEEK_SET);
        char section_name[256];  // Arbitrary size; vulnerable to overflow
        if (fread(section_name, 1, 255, file) < 0) {
            perror("Failed to read section name");
            fclose(file);
            exit(1);
        }
        section_name[255] = '\0';  // Null-terminate

        // Print the section name (dangerous, might overflow the buffer)
        printf("Section %d: %s\n", i, section_name);
    }

    fclose(file);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <ELF filename>\n", argv[0]);
        return 1;
    }

    parse_elf(argv[1]);

    return 0;
}
