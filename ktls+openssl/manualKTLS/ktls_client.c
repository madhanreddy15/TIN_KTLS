#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/tls.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/net.h>
#include <time.h>

#define PORT 4433
#ifndef TCP_ULP
#define TCP_ULP 31
#endif
#define FILE_OUT "receivedFile.txt"
#define SERVER_ADDRESS "127.0.0.1"

void setup_tls_rx(int sockfd, SSL *ssl) {
    unsigned char key[32];  // AES-GCM key length
    unsigned char iv[12];   // AES-GCM IV length

    // Extract the keying material from the SSL session
    if (SSL_export_keying_material(ssl, key, sizeof(key), NULL, 0, NULL, 0, 0) <= 0) {
        perror("SSL_export_keying_material failed");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Initialize IV 
    memset(iv, 1, sizeof(iv)); 

    struct tls12_crypto_info_aes_gcm_128 crypto;
    memset(&crypto, 0, sizeof(crypto));

    crypto.info.version = TLS_1_2_VERSION;
    crypto.info.cipher_type = TLS_CIPHER_AES_GCM_128;

    memcpy(crypto.key, key, sizeof(crypto.key));
    memcpy(crypto.iv, iv, sizeof(crypto.iv));

    memset(crypto.salt, 3, TLS_CIPHER_AES_GCM_128_SALT_SIZE);  // Optional
    memset(crypto.rec_seq, 4, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);  // Optional

    // Set the decryption configuration for RX (receive direction)
    if (setsockopt(sockfd, SOL_TLS, TLS_RX, &crypto, sizeof(crypto)) < 0) {
        perror("setsockopt TLS_RX failed");
        exit(EXIT_FAILURE);
    }

    printf("KTLS TLS_RX configured with OpenSSL-derived keys\n");
}

int main() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

    if (!SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION)) {
        fprintf(stderr, "Failed to set max protocol version to TLS 1.2\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
        fprintf(stderr, "Failed to set min protocol version to TLS 1.2\n");
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
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    printf("TLS handshake complete\n");

    // Enable TLS protocol on the socket (sets tcp->ulp_data = tls)
    const char *ulp_name = "tls";
    if (setsockopt(sockfd, SOL_TCP, TCP_ULP, ulp_name, strlen(ulp_name)) < 0) {
        if (errno != EEXIST) {
            perror("setsockopt TCP_ULP");
            exit(EXIT_FAILURE);
        } else {
            printf("TCP_ULP already set — continuing\n");
        }
    }

    setup_tls_rx(sockfd, ssl);

    int out_fd = open(FILE_OUT, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) { 
        perror("open");
        exit(EXIT_FAILURE); 
    }

    // Receiving file size to avoid fetching extra SSL shutdown alerts 
    uint32_t file_size_net;
    if (recv(sockfd, &file_size_net, sizeof(file_size_net), MSG_WAITALL) != sizeof(file_size_net)) {
        perror("recv file size");
        exit(EXIT_FAILURE);
    }
    uint32_t file_size = ntohl(file_size_net);
    printf("Expecting %u bytes of file content\n", file_size);

    struct timespec start,end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    // Receiving actual file data
    char buf[4096];
    ssize_t received = 0;
    while (received < file_size) {
        ssize_t n = recv(sockfd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        if ((received + n) > file_size) n = file_size - received;  // Trim excess
        write(out_fd, buf, n);
        received += n;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed_ms = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1e6;
    double mb = file_size / (1024.0 * 1024.0);

    printf("Received %zd bytes\n", received);
    printf("File received.\n");
    printf("Latency: %.6f milliseconds\n", elapsed_ms);
    printf("Throughput: %.2f MB/s\n", mb / (elapsed_ms / 1000.0)); 

    close(out_fd);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}

