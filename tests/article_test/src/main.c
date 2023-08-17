#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int dumb(char *progname) {
    switch(strlen(progname)) {
        case 5: {
            puts("Little");
            break;
        }

        case 10: {
            puts("Medium");
            break;
        }

        default: {
            puts("Unknow");
            break;
        }

    }

    return 0;
}

int main(int argc, char **argv) {
    return dumb(argv[0]);
}