#define _GNU_SOURCE
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/tls.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <linux/net.h>
#include <time.h>

#define PORT 4433
#define SERVER_ADDRESS "127.0.0.1"
#ifndef TCP_ULP
#define TCP_ULP 31
#endif
#define FILE_OUT "receivedFile.txt"

void setup_tls_rx(int sockfd) {
    struct tls12_crypto_info_aes_gcm_128 crypto_info;
    memset(&crypto_info, 0, sizeof(crypto_info));

    crypto_info.info.version = TLS_1_2_VERSION;
    crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;

    // Same dummy keys as server
    memset(crypto_info.iv, 1, TLS_CIPHER_AES_GCM_128_IV_SIZE);
    memset(crypto_info.key, 2, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
    memset(crypto_info.salt, 3, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
    memset(crypto_info.rec_seq, 4, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);

    if (setsockopt(sockfd, SOL_TLS, TLS_RX, &crypto_info, sizeof(crypto_info)) < 0) {
        perror("setsockopt TLS_RX");
        exit(EXIT_FAILURE);
    }

    printf("TLS_RX configured successfully on client\n");
}

int main() {
    int sockfd;
    struct sockaddr_in serv_addr;
    char buffer[4096] = {0};

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_ADDRESS, &serv_addr.sin_addr);

    connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    printf("Connected to server\n");

    // Enable TLS protocol on the socket (sets tcp->ulp_data = tls)
    const char *ulp_name = "tls";
    if (setsockopt(sockfd, SOL_TCP, TCP_ULP, ulp_name, strlen(ulp_name)) < 0) {
        perror("setsockopt TCP_ULP");
        exit(EXIT_FAILURE);
    }

    setup_tls_rx(sockfd);

    int out_fd = open(FILE_OUT, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) { perror("open out"); exit(1); }

    struct timespec start,end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    char buf[4096];
    ssize_t n, total = 0;
    while ((n = recv(sockfd, buf, sizeof(buf), 0)) > 0) {
        write(out_fd, buf, n);
        total += n;
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed_ms = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1e6;
    double mb = total / (1024.0 * 1024.0);

    printf("File received.\n");
    printf("Latency: %.6f milliseconds\n", elapsed_ms);
    printf("Throughput: %.2f MB/s\n", mb / (elapsed_ms / 1000.0)); 

    close(out_fd);
    close(sockfd);
    return 0;
}

