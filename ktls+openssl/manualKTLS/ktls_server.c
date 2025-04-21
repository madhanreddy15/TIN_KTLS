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
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/net.h>
#include <time.h>

#define PORT 4433
#define FILE_TO_SEND "testfile.txt"
#ifndef TCP_ULP
#define TCP_ULP 31
#endif

void setup_tls_tx(int sockfd, SSL *ssl) {
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

    memset(crypto.salt, 3, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
    memset(crypto.rec_seq, 4, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);

    // Set the encryption configuration for TX (send direction)
    if (setsockopt(sockfd, SOL_TLS, TLS_TX, &crypto, sizeof(crypto)) < 0) {
        perror("setsockopt TLS_TX failed");
        exit(EXIT_FAILURE);
    }

    printf("KTLS TLS_TX configured with OpenSSL-derived keys\n");
}

int main() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());

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

    if (!SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) ||
        !SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM)) {
        printf("Error fetching server.crt and server.key \n");    
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
    printf("Server listening...\n");

    struct sockaddr_in client_addr;
    socklen_t len = sizeof(client_addr);
    while(1)
    {
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &len);
        printf("Client connected\n");

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);
        if (SSL_accept(ssl) <= 0) {
            printf("Error accepting SSL connection\n");
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        
        printf("TLS handshake complete\n");

        // Enable TLS protocol on the socket (sets tcp->ulp_data = tls)
        const char *ulp_name = "tls";
        if (setsockopt(client_fd, SOL_TCP, TCP_ULP, ulp_name, strlen(ulp_name)) < 0) {
            if (errno != EEXIST) {
                perror("setsockopt TCP_ULP");
                exit(EXIT_FAILURE);
            } else {
                printf("TCP_ULP already set — continuing\n");
            }
        }

        setup_tls_tx(client_fd, ssl);

        int file_fd = open(FILE_TO_SEND, O_RDONLY);
        if (file_fd < 0) {
            perror("open");
            exit(EXIT_FAILURE);
        }

        // Seding file size to avoid decrypting alerts at receiver's side
        struct stat st;
        fstat(file_fd, &st);
        uint32_t file_size = htonl((uint32_t)st.st_size);
        if (send(client_fd, &file_size, sizeof(file_size), 0) != sizeof(file_size)) {
            perror("send file_size");
            exit(EXIT_FAILURE);
        }

        struct timespec start,end;
        clock_gettime(CLOCK_MONOTONIC, &start);

        off_t offset = 0;
        ssize_t sent = sendfile(client_fd, file_fd, &offset, ntohl(file_size));
        if (sent < 0) {
            perror("sendfile");
            exit(EXIT_FAILURE);
        }
        else {
            clock_gettime(CLOCK_MONOTONIC, &end);

            double elapsed_ms = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1e6;
            double mb = sent / (1024.0 * 1024.0);

            printf("Sent %zd bytes\n", sent);

            printf("Latency: %.6f milliseconds\n", elapsed_ms);
            printf("Throughput: %.2f MB/s\n", mb / (elapsed_ms / 1000.0));    
        }

        close(file_fd);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }
    
    close(server_fd);
    SSL_CTX_free(ctx);
    return 0;
}

