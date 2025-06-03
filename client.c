#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 12345
#define BUFFER_SIZE 1024
#define USERNAME_LEN 32

int sockfd;
SSL *ssl;

void *receive_handler(void *arg) {
    char buffer[BUFFER_SIZE];
    int len;

    while ((len = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[len] = '\0';
        printf("\r%s\n> ", buffer);
        fflush(stdout);
    }

    printf("\nDisconnected from server.\n");
    exit(EXIT_FAILURE);
}

int main() {
    struct sockaddr_in server_addr;
    char message[BUFFER_SIZE];
    char username[USERNAME_LEN];
    char password[USERNAME_LEN];

    printf("Enter your username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = '\0';

    printf("Enter your password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = '\0';

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Nếu bạn có CA để xác thực server, load CA tại đây
    // SSL_CTX_load_verify_locations(ctx, "ca_cert.pem", NULL);

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect failed");
        exit(EXIT_FAILURE);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        close(sockfd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    char credentials[BUFFER_SIZE];
    snprintf(credentials, sizeof(credentials), "%s:%s", username, password);
    SSL_write(ssl, credentials, strlen(credentials));

    char response[BUFFER_SIZE];
    int len = SSL_read(ssl, response, sizeof(response) - 1);
    if (len <= 0) {
        printf("Server closed connection.\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sockfd);
        exit(EXIT_FAILURE);
    }
    response[len] = '\0';

    if (strcmp(response, "AUTH_SUCCESS") != 0) {
        printf("Login failed: %s\n", response);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("Connected to chat server as '%s'.\n", username);

    pthread_t recv_thread;
    pthread_create(&recv_thread, NULL, receive_handler, NULL);

    while (1) {
        printf("> ");
        if (fgets(message, sizeof(message), stdin) == NULL)
            break;

        SSL_write(ssl, message, strlen(message));
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(sockfd);

    return 0;
}

