#define _GNU_SOURCE
#include <arpa/inet.h>
#include <linux/tls.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/net.h>
#include <netinet/tcp.h>   // For SOL_TCP
#include <time.h>

#define PORT 4433
#define FILE_TO_SEND "testfile.txt"
#ifndef TCP_ULP
#define TCP_ULP 31
#endif

void setup_tls_tx(int sockfd) {
    struct tls12_crypto_info_aes_gcm_128 crypto_info;
    memset(&crypto_info, 0, sizeof(crypto_info));

    crypto_info.info.version = TLS_1_2_VERSION;
    crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;

    // Fill in with dummy/test keys
    memset(crypto_info.iv, 1, TLS_CIPHER_AES_GCM_128_IV_SIZE);
    memset(crypto_info.key, 2, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
    memset(crypto_info.salt, 3, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
    memset(crypto_info.rec_seq, 4, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);

    if (setsockopt(sockfd, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info)) < 0) {
        perror("setsockopt TLS_TX");
        exit(EXIT_FAILURE);
    }

    printf(" TLS_TX configured successfully on server\n");
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);
    int opt = 1;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 5);

    while(1)
    {
        printf("Waiting for connection...\n");
        new_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen);
        if (new_socket < 0) 
        { 
            perror("Accept");
            exit(EXIT_FAILURE); 
        }
        printf("Client connected!\n");

        // Enable TLS protocol on the socket (sets tcp->ulp_data = tls)
        const char *ulp_name = "tls";
        if (setsockopt(new_socket, SOL_TCP, TCP_ULP, ulp_name, strlen(ulp_name)) < 0) {
            perror("setsockopt TCP_ULP");
            exit(EXIT_FAILURE);
        }

        setup_tls_tx(new_socket);

        int file_fd = open(FILE_TO_SEND, O_RDONLY);
        if (file_fd < 0) {
            perror("open file");
            exit(EXIT_FAILURE);
        }

        struct stat st;
        fstat(file_fd, &st);
        off_t offset = 0;

        printf("Sending file (%ld bytes)...\n", st.st_size);

        struct timespec start,end;
        clock_gettime(CLOCK_MONOTONIC, &start);

        ssize_t sent = sendfile(new_socket, file_fd, &offset, st.st_size);
        if (sent < 0) {
            perror("sendfile");
        } else {
            clock_gettime(CLOCK_MONOTONIC, &end);

            // double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
            double elapsed_ms = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1e6;
            double mb = sent / (1024.0 * 1024.0);

            printf("Sent %zd bytes\n", sent);

            printf("Latency: %.6f milliseconds\n", elapsed_ms);
            printf("Throughput: %.2f MB/s\n", mb / (elapsed_ms / 1000.0));    
        }
        close(file_fd);
        close(new_socket);
    }

    
    close(server_fd);
    return 0;
}

