#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/hmac.h>
#include "mission.h"

#define BUFFER_SIZE 2048
#define SHARED_SECRET "MISSION-NETWORK-KEY-2026"

static int send_all(int sock, const char *text) {
    size_t total = 0, length = strlen(text);
    while (total < length) {
        ssize_t sent = send(sock, text + total, length - total, 0);
        if (sent <= 0) return 0;
        total += (size_t)sent;
    }
    return 1;
}

static int recv_line_socket(int sock, char *buffer, int size) {
    int used = 0;
    while (used < size - 1) {
        char c;
        ssize_t received = recv(sock, &c, 1, 0);
        if (received <= 0) return 0;
        if (c == '\n') break;
        if (c != '\r') buffer[used++] = c;
    }
    buffer[used] = '\0';
    return 1;
}

static void hmac_hex(const char *message, char output[65]) {
    unsigned int length = 0;
    unsigned char digest[EVP_MAX_MD_SIZE];
    HMAC(EVP_sha256(), SHARED_SECRET, (int)strlen(SHARED_SECRET),
         (const unsigned char *)message, strlen(message), digest, &length);
    for (unsigned int i = 0; i < length; i++) sprintf(output + i * 2, "%02x", digest[i]);
    output[length * 2] = '\0';
}

int run_client(const char *host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr;
    char response[BUFFER_SIZE], line[BUFFER_SIZE], payload[1000];
    unsigned long sequence = 1;

    if (sock < 0) { perror("socket"); return 1; }
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, host, &server_addr.sin_addr) != 1) {
        printf("Invalid IPv4 address.\n"); close(sock); return 1;
    }
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect"); close(sock); return 1;
    }

    if (recv_line_socket(sock, response, sizeof(response))) printf("Server: %s\n", response);
    send_all(sock, "AUTH|satellite1|orbit123\n");
    if (!recv_line_socket(sock, response, sizeof(response))) { close(sock); return 1; }
    printf("Server: %s\n", response);
    if (strncmp(response, "201|", 4) != 0) { close(sock); return 1; }

    while (1) {
        int choice;
        printf("\nSatellite Client\n");
        printf("1. Send heartbeat\n2. Send telemetry\n3. Request mission status\n4. Request orbit command\n0. Disconnect\n");
        printf("Select an option: ");
        if (scanf("%d", &choice) != 1) { clear_input_buffer(); printf("Invalid input.\n"); continue; }
        clear_input_buffer();

        if (choice == 0) {
            send_all(sock, "LOGOUT\n");
            if (recv_line_socket(sock, response, sizeof(response))) printf("Server: %s\n", response);
            break;
        }

        const char *type;
        if (choice == 1) { type = "PING"; strcpy(payload, "HEARTBEAT"); }
        else if (choice == 2) {
            type = "TELEMETRY";
            printf("Telemetry text (example temperature=24,battery=88): ");
            read_line(payload, sizeof(payload));
            if (strchr(payload, '|') != NULL || strlen(payload) == 0) { printf("Payload cannot be empty or contain |.\n"); continue; }
        } else if (choice == 3) { type = "COMMAND"; strcpy(payload, "REQUEST_STATUS"); }
        else if (choice == 4) { type = "COMMAND"; strcpy(payload, "REQUEST_ORBIT"); }
        else { printf("Invalid option.\n"); continue; }

        char signed_text[1200], signature[65];
        snprintf(signed_text, sizeof(signed_text), "%s|%lu|%s", type, sequence, payload);
        hmac_hex(signed_text, signature);
        snprintf(line, sizeof(line), "%s|%s\n", signed_text, signature);
        if (!send_all(sock, line) || !recv_line_socket(sock, response, sizeof(response))) {
            printf("Connection lost.\n"); break;
        }
        printf("Server: %s\n", response);
        sequence++;
    }

    close(sock);
    return 0;
}
