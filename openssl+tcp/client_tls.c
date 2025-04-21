#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#define PORT 4433
#define FILE_OUT "receivedFile.txt"
#define SERVER_ADDRESS "127.0.0.1"

int main() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

    if (!SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION) ||
        !SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
        fprintf(stderr, "Failed to set TLS version to 1.2\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
    };
    inet_pton(AF_INET, SERVER_ADDRESS, &addr.sin_addr);

    connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "SSL_connect failed\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    printf("TLS handshake complete\n");

    int out_fd = open(FILE_OUT, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    uint32_t file_size_net;
    if (SSL_read(ssl, &file_size_net, sizeof(file_size_net)) != sizeof(file_size_net)) {
        perror("SSL_read file size");
        exit(EXIT_FAILURE);
    }
    uint32_t file_size = ntohl(file_size_net);
    printf("Expecting %u bytes of file content\n", file_size);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    char buf[4096];
    ssize_t received = 0;
    while (received < file_size) {
        ssize_t n = SSL_read(ssl, buf, sizeof(buf));
        if (n <= 0) break;
        if ((received + n) > file_size) n = file_size - received;
        write(out_fd, buf, n);
        received += n;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed_ms = (end.tv_sec - start.tv_sec) * 1000.0 +
                        (end.tv_nsec - start.tv_nsec) / 1e6;
    double mb = received / (1024.0 * 1024.0);

    printf("Received %zd bytes\n", received);
    printf("Latency: %.6f milliseconds\n", elapsed_ms);
    printf("Throughput: %.2f MB/s\n", mb / (elapsed_ms / 1000.0));

    close(out_fd);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}
