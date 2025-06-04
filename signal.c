#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/select.h>
#include <string.h>

#define BUF_SIZE 100
#define TIMEOUT_SECONDS 10

int main() {
    char buffer[BUF_SIZE];
    fd_set readfds;
    struct timeval timeout;

    printf("Start typing. If you stop for %d seconds, program will exit.\n", TIMEOUT_SECONDS);

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);

        timeout.tv_sec = TIMEOUT_SECONDS;
        timeout.tv_usec = 0;

        int ready = select(STDIN_FILENO + 1, &readfds, NULL, NULL, &timeout);

        if (ready == -1) {
            perror("select error");
            exit(1);
        } else if (ready == 0) {
            // Timeout: không nhập gì trong 10 giây
            printf("\nTimeout! No input in %d seconds. Exiting...\n", TIMEOUT_SECONDS);
            break;
        } else {
            // Có dữ liệu nhập
            if (fgets(buffer, BUF_SIZE, stdin) != NULL) {
                printf("You typed: %s", buffer);
            }
        }
    }

    return 0;
}

