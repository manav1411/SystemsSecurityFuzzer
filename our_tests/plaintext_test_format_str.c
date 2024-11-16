#include <stdio.h>

void vulnerableFunction(char* input) {
    printf(input); // Vulnerable function
}

int main() {
    char input[50];
    printf("Enter a string: ");
    fgets(input, sizeof(input), stdin);
    vulnerableFunction(input);
    return 0;
}