#include <hpdf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Vulnerable function that doesn't check the size of the input buffer
void unsafe_copy_to_buffer(const char *input) {
    char buffer[256];  // Vulnerable buffer size
    strcpy(buffer,
           input);  // Potential buffer overflow if input exceeds 255 characters
    printf("Copied to buffer: %s\n", buffer);
}

// Function that doesn't handle errors correctly
void create_pdf_with_vulnerabilities(const char *filename) {
    HPDF_Doc pdf;
    HPDF_Page page;

    // This line could potentially cause a memory leak if pdf creation fails
    pdf = HPDF_New(NULL, NULL);
    if (!pdf) {
        printf("Error: Unable to create PDF object\n");
        return;  // Should ideally handle cleanup here
    }

    page = HPDF_AddPage(pdf);
    HPDF_Page_SetSize(page, HPDF_PAGE_SIZE_A4, HPDF_PAGE_PORTRAIT);

    // Unsafe call that can cause problems
    const char *long_string =
        "This is a very long string that could potentially cause a buffer "
        "overflow or memory corruption if not handled properly.";
    unsafe_copy_to_buffer(long_string);  // This is a dangerous call!

    // Adding text to the PDF (not sanitized properly)
    HPDF_Page_BeginText(page);
    HPDF_Page_SetFontAndSize(page, HPDF_GetFont(pdf, "Helvetica", NULL), 12);
    HPDF_Page_TextOut(page, 50, 750,
                      "Vulnerable PDF with buffer overflow example.");
    HPDF_Page_EndText(page);

    // Saving the PDF to a file
    if (HPDF_SaveToFile(pdf, filename) != HPDF_OK) {
        printf("Error: Failed to save PDF to file\n");
    }

    // Vulnerable cleanup: not checking if the memory is freed correctly
    HPDF_Free(pdf);  // Can result in memory leak if the PDF creation fails
}

int main() {
    // Try to create a PDF file with a fixed name
    create_pdf_with_vulnerabilities("vulnerable_output.pdf");

    return 0;
}
