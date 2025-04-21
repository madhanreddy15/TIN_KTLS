#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>

#define PORT 4433
#define FILE_TO_SEND "testfile.txt"

int main() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

    if (!SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION) ||
        !SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
        fprintf(stderr, "Failed to set TLS version to 1.2\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) ||
        !SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM)) {
        fprintf(stderr, "Failed to load certificate or key\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(PORT),
    };

    bind(server_fd, (struct sockaddr *)&addr, sizeof(addr));
    listen(server_fd, 5);
    printf("Server listening on port %d...\n", PORT);

    struct sockaddr_in client_addr;
    socklen_t len = sizeof(client_addr);
    while (1) {
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &len);
        printf("Client connected\n");

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);
        if (SSL_accept(ssl) <= 0) {
            fprintf(stderr, "SSL handshake failed\n");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }

        printf("TLS handshake complete\n");

        int file_fd = open(FILE_TO_SEND, O_RDONLY);
        if (file_fd < 0) {
            perror("open");
            exit(EXIT_FAILURE);
        }

        struct stat st;
        fstat(file_fd, &st);
        uint32_t file_size = htonl((uint32_t)st.st_size);
        if (SSL_write(ssl, &file_size, sizeof(file_size)) != sizeof(file_size)) {
            perror("SSL_write file size");
            exit(EXIT_FAILURE);
        }

        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);

        char buf[4096];
        ssize_t sent_total = 0, n;
        while ((n = read(file_fd, buf, sizeof(buf))) > 0) {
            if (SSL_write(ssl, buf, n) <= 0) {
                perror("SSL_write");
                exit(EXIT_FAILURE);
            }
            sent_total += n;
        }

        clock_gettime(CLOCK_MONOTONIC, &end);

        double elapsed_ms = (end.tv_sec - start.tv_sec) * 1000.0 +
                            (end.tv_nsec - start.tv_nsec) / 1e6;
        double mb = sent_total / (1024.0 * 1024.0);

        printf("Sent %zd bytes\n", sent_total);
        printf("Latency: %.6f milliseconds\n", elapsed_ms);
        printf("Throughput: %.2f MB/s\n", mb / (elapsed_ms / 1000.0));

        close(file_fd);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    return 0;
}
