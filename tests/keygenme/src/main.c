#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void trigger(char c, char high, char low) {
    if(((c & 0xf) ^ low) | ((c >> 4) ^ high)) {
        exit(1);
    }
    return;
}

int check(char *licence_key) {
    char key[14] = {0x7, 0x4, 0x6, 0x8, 0x6, 0x5, 0x5, 0xf, 0x6, 0xb, 0x6, 0x5, 0x7, 0x9};

    if(strlen(licence_key) != 7) {
        exit(1);
    }

    for(int i=0; i<sizeof(key)/2; i++) {
        trigger(licence_key[i], key[2*i], key[2*i+1]);
    }

    return 0;
}

int main(int argc, char **argv) {
    if(argc != 2) {
        printf("Usage : %s LICENSE_KEY\n", argv[0]);
        return 1;
    }
    check(argv[1]);
    puts("Great");
    return 0;
}