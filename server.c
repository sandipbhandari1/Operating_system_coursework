#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include "mission.h"

#define MAX_CLIENTS 20
#define BUFFER_SIZE 2048
#define SHARED_SECRET "MISSION-NETWORK-KEY-2026"
#define AUTH_USER "satellite1"
#define AUTH_PASSWORD "orbit123"

static volatile sig_atomic_t server_running = 1;
static int listen_socket = -1;
static pthread_mutex_t network_log_mutex = PTHREAD_MUTEX_INITIALIZER;

static void stop_server(int sig) {
    (void)sig;
    server_running = 0;
    if (listen_socket >= 0) close(listen_socket);
}

static void network_log(const char *client, const char *event) {
    FILE *fp;
    pthread_mutex_lock(&network_log_mutex);
    fp = fopen("task4_server.log", "a");
    if (fp != NULL) {
        fprintf(fp, "client=%s | %s\n", client, event);
        fclose(fp);
    }
    pthread_mutex_unlock(&network_log_mutex);
}

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

static int constant_time_equal(const char *a, const char *b) {
    size_t len_a = strlen(a), len_b = strlen(b);
    if (len_a != len_b) return 0;
    return CRYPTO_memcmp(a, b, len_a) == 0;
}

typedef struct {
    int socket_fd;
    char address[64];
} ClientInfo;

static void *client_worker(void *arg) {
    ClientInfo *info = (ClientInfo *)arg;
    int sock = info->socket_fd;
    char address[64];
    char line[BUFFER_SIZE];
    unsigned long last_sequence = 0;
    int authenticated = 0;

    strncpy(address, info->address, sizeof(address) - 1);
    address[sizeof(address) - 1] = '\0';
    free(info);

    network_log(address, "CONNECTED");
    send_all(sock, "200|SPACE_MISSION_SERVER_READY\n");

    while (recv_line_socket(sock, line, sizeof(line))) {
        if (strlen(line) > 1500) {
            send_all(sock, "400|MESSAGE_TOO_LONG\n");
            continue;
        }

        if (!authenticated) {
            char command[16], user[64], password[64];
            if (sscanf(line, "%15[^|]|%63[^|]|%63[^\n]", command, user, password) == 3 &&
                strcmp(command, "AUTH") == 0 && strcmp(user, AUTH_USER) == 0 && strcmp(password, AUTH_PASSWORD) == 0) {
                authenticated = 1;
                send_all(sock, "201|AUTHENTICATED\n");
                network_log(address, "AUTH_SUCCESS");
            } else {
                send_all(sock, "401|AUTHENTICATION_FAILED\n");
                network_log(address, "AUTH_FAILED");
                break;
            }
            continue;
        }

        if (strcmp(line, "LOGOUT") == 0) {
            send_all(sock, "200|GOODBYE\n");
            break;
        }

        char type[32], payload[1024], received_hmac[65];
        unsigned long sequence;
        if (sscanf(line, "%31[^|]|%lu|%1023[^|]|%64s", type, &sequence, payload, received_hmac) != 4) {
            send_all(sock, "400|INVALID_PROTOCOL\n");
            continue;
        }

        if (sequence <= last_sequence) {
            send_all(sock, "409|REPLAY_OR_OLD_SEQUENCE\n");
            network_log(address, "REPLAY_REJECTED");
            continue;
        }

        char signed_text[1200], expected_hmac[65];
        snprintf(signed_text, sizeof(signed_text), "%s|%lu|%s", type, sequence, payload);
        hmac_hex(signed_text, expected_hmac);
        if (!constant_time_equal(expected_hmac, received_hmac)) {
            send_all(sock, "403|INVALID_MESSAGE_SIGNATURE\n");
            network_log(address, "HMAC_FAILED");
            continue;
        }

        last_sequence = sequence;
        if (strcmp(type, "PING") == 0) {
            send_all(sock, "200|PONG\n");
        } else if (strcmp(type, "TELEMETRY") == 0) {
            char response[1200];
            snprintf(response, sizeof(response), "202|TELEMETRY_ACCEPTED|%s\n", payload);
            send_all(sock, response);
            network_log(address, "TELEMETRY_ACCEPTED");
        } else if (strcmp(type, "COMMAND") == 0) {
            if (strcmp(payload, "REQUEST_STATUS") == 0)
                send_all(sock, "203|COMMAND_RESPONSE|STATUS_NOMINAL\n");
            else if (strcmp(payload, "REQUEST_ORBIT") == 0)
                send_all(sock, "203|COMMAND_RESPONSE|MAINTAIN_CURRENT_ORBIT\n");
            else
                send_all(sock, "422|COMMAND_NOT_ALLOWED\n");
        } else {
            send_all(sock, "400|UNKNOWN_MESSAGE_TYPE\n");
        }
    }

    network_log(address, "DISCONNECTED");
    close(sock);
    return NULL;
}

int run_server(int port) {
    struct sockaddr_in server_addr;
    signal(SIGINT, stop_server);
    signal(SIGTERM, stop_server);
    server_running = 1;

    listen_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_socket < 0) { perror("socket"); return 1; }

    int option = 1;
    setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons((unsigned short)port);

    if (bind(listen_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind"); close(listen_socket); return 1;
    }
    if (listen(listen_socket, MAX_CLIENTS) < 0) {
        perror("listen"); close(listen_socket); return 1;
    }

    printf("Mission server listening on port %d. Press Ctrl+C to stop.\n", port);
    while (server_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_socket = accept(listen_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) {
            if (server_running && errno != EINTR) perror("accept");
            continue;
        }

        struct timeval timeout = {120, 0};
        setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        setsockopt(client_socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

        ClientInfo *info = malloc(sizeof(ClientInfo));
        if (info == NULL) { close(client_socket); continue; }
        info->socket_fd = client_socket;
        inet_ntop(AF_INET, &client_addr.sin_addr, info->address, sizeof(info->address));

        pthread_t thread;
        if (pthread_create(&thread, NULL, client_worker, info) != 0) {
            close(client_socket); free(info); continue;
        }
        pthread_detach(thread);
    }

    if (listen_socket >= 0) close(listen_socket);
    listen_socket = -1;
    printf("Mission server stopped.\n");
    return 0;
}
