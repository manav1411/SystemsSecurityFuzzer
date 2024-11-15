#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 1024

// simple program to extract text from a PDF file, 1024 byte buffer //

// Helper function to extract words from text blocks
void extract_words(const char *data, size_t length) {
    int inside_text = 0;
    int word_count = 0;
    for (size_t i = 0; i < length; i++) {
        if (data[i] == '(') {
            inside_text = 1;
        } else if (data[i] == ')') {
            inside_text = 0;
            printf(" "); // Separate words
        } else if (inside_text) {
            putchar(data[i]);
            if (++word_count >= 10) {
                printf("\n... (Truncated output)\n");
                return;
            }
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: ./pdfViewer <pdf-file>\n");
        return 1;
    }

    const char *filename = argv[1];
    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("Error: Could not open file '%s'\n", filename);
        return 1;
    }

    char buffer[BUFFER_SIZE];
    size_t bytes_read;
    int found_text = 0;

    printf("Extracted text from '%s':\n", filename);

    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        if (found_text) {
            extract_words(buffer, bytes_read);
        } else {
            // Look for "BT" (Begin Text) to start parsing text blocks
            char *start = strstr(buffer, "BT");
            if (start) {
                found_text = 1;
                extract_words(start, bytes_read - (start - buffer));
            }
        }

        if (found_text && bytes_read < BUFFER_SIZE) {
            break;
        }
    }

    if (!found_text) {
        printf("No text found in the PDF.\n");
    }

    fclose(file);
    return 0;
}
