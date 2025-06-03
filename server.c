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
#define MAX_CLIENTS 100
#define BUFFER_SIZE 1024
#define USERNAME_LEN 32
#define HISTORY_LINES 100

typedef struct {
    SSL *ssl;                 // Thay sockfd bằng SSL*
    int sockfd;               // vẫn giữ sockfd để close socket
    char username[USERNAME_LEN];
} client_t;

client_t *clients[MAX_CLIENTS];
int client_count = 0;
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

// Hàm xác thực user giống bạn
int authenticate_user(const char *username, const char *password) {
    FILE *file = fopen("accounts.txt", "r");
    if (!file) {
        perror("Failed to open accounts file");
        return 0;
    }

    char line[BUFFER_SIZE];
    char user[USERNAME_LEN], pass[USERNAME_LEN];

    while (fgets(line, sizeof(line), file)) {
        if (sscanf(line, "%[^:]:%s", user, pass) == 2) {
            if (strcmp(user, username) == 0 && strcmp(pass, password) == 0) {
                fclose(file);
                return 1;
            }
        }
    }

    fclose(file);
    return 0;
}

void save_message_to_file(const char *message) {
    FILE *file = fopen("chat_history.txt", "a");
    if (file) {
        fprintf(file, "%s", message);
        fclose(file);
    }
}

void send_chat_history(client_t *cli) {
    FILE *file = fopen("chat_history.txt", "r");
    if (!file) return;

    char *lines[HISTORY_LINES];
    memset(lines, 0, sizeof(lines));

    int count = 0;
    char buffer[BUFFER_SIZE];

    while (fgets(buffer, sizeof(buffer), file)) {
        if (lines[count % HISTORY_LINES]) {
            free(lines[count % HISTORY_LINES]);
        }
        lines[count % HISTORY_LINES] = strdup(buffer);
        if (!lines[count % HISTORY_LINES]) {
            perror("strdup failed");
            fclose(file);
            return;
        }
        count++;
    }

    int start = (count > HISTORY_LINES) ? count % HISTORY_LINES : 0;
    int total = (count > HISTORY_LINES) ? HISTORY_LINES : count;

    for (int i = 0; i < total; i++) {
        int index = (start + i) % HISTORY_LINES;
        if (lines[index]) {
            SSL_write(cli->ssl, lines[index], strlen(lines[index]));
            free(lines[index]);
        }
    }

    fclose(file);
}

void broadcast_message(char *message, int sender_fd) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < client_count; i++) {
        if (clients[i]->sockfd != sender_fd) {
            SSL_write(clients[i]->ssl, message, strlen(message));
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

void remove_client(int sockfd) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < client_count; i++) {
        if (clients[i]->sockfd == sockfd) {
            SSL_shutdown(clients[i]->ssl);
            SSL_free(clients[i]->ssl);
            close(clients[i]->sockfd);
            free(clients[i]);
            for (int j = i; j < client_count - 1; j++) {
                clients[j] = clients[j + 1];
            }
            client_count--;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

void *handle_client(void *arg) {
    client_t *cli = (client_t *)arg;
    char buffer[BUFFER_SIZE];
    char message[BUFFER_SIZE + USERNAME_LEN + 32];
    int len;

    // Nhận credentials: username:password
    len = SSL_read(cli->ssl, buffer, sizeof(buffer) - 1);
    if (len <= 0) {
        remove_client(cli->sockfd);
        free(cli);
        pthread_exit(NULL);
    }
    buffer[len] = '\0';

    char *sep = strchr(buffer, ':');
    if (!sep) {
        SSL_write(cli->ssl, "Invalid format", 14);
        remove_client(cli->sockfd);
        free(cli);
        pthread_exit(NULL);
    }

    *sep = '\0';
    char *username = buffer;
    char *password = sep + 1;

    if (!authenticate_user(username, password)) {
        SSL_write(cli->ssl, "Authentication failed", 22);
        remove_client(cli->sockfd);
        free(cli);
        pthread_exit(NULL);
    }

    SSL_write(cli->ssl, "AUTH_SUCCESS", 12);
    strncpy(cli->username, username, USERNAME_LEN - 1);

    printf("User '%s' connected.\n", cli->username);
    snprintf(message, sizeof(message), "*** User '%s' has joined the chat ***\n", cli->username);
    broadcast_message(message, cli->sockfd);
    save_message_to_file(message);

    send_chat_history(cli);

    while ((len = SSL_read(cli->ssl, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[len] = '\0';
        snprintf(message, sizeof(message), "[%s]: %s", cli->username, buffer);
        printf("%s", message);
        broadcast_message(message, cli->sockfd);
        save_message_to_file(message);
    }

    printf("User '%s' disconnected.\n", cli->username);
    snprintf(message, sizeof(message), "*** User '%s' has left the chat ***\n", cli->username);
    broadcast_message(message, cli->sockfd);
    save_message_to_file(message);

    remove_client(cli->sockfd);
    free(cli);
    pthread_exit(NULL);
}

int main() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 10) < 0) {
        perror("listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("TLS chat server listening on port %d...\n", PORT);

    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            perror("accept failed");
            continue;
        }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            close(client_fd);
            SSL_free(ssl);
            continue;
        }

        client_t *cli = malloc(sizeof(client_t));
        cli->ssl = ssl;
        cli->sockfd = client_fd;
        memset(cli->username, 0, sizeof(cli->username));

        pthread_mutex_lock(&clients_mutex);
        if (client_count >= MAX_CLIENTS) {
            printf("Max clients reached.\n");
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client_fd);
            free(cli);
            pthread_mutex_unlock(&clients_mutex);
            continue;
        }
        clients[client_count++] = cli;
        pthread_mutex_unlock(&clients_mutex);

        pthread_t tid;
        pthread_create(&tid, NULL, handle_client, cli);
        pthread_detach(tid);

        printf("Accepted TLS connection from %s:%d\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    return 0;
}

