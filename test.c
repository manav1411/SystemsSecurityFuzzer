
// C program that takes in 1 line of value, and prints that.

#include <stdio.h>
#include <string.h>

int main() {
    char str[20];
    printf("Enter a value: ");
    scanf("%s", str);
    if (strcmp(str, "Python") == 0) {
        //prints error
        printf("Error: you entered Python, which sucks!!\n");
        return 1;
    }
    printf("You entered: %s\n", str);
    return 0;
}