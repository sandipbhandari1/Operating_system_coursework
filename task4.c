#include <stdio.h>
#include <string.h>
#include "mission.h"

void task4_menu(void) {
    int choice, port;
    char host[64];
    while (1) {
        printf("\nTask 4 - Satellite Client-Server Communication\n");
        printf("1. Start ground-control server\n");
        printf("2. Start satellite client\n");
        printf("3. Show protocol summary\n");
        printf("0. Return to main menu\n");
        printf("Select an option: ");

        if (scanf("%d", &choice) != 1) { clear_input_buffer(); printf("Invalid input.\n"); continue; }
        clear_input_buffer();

        if (choice == 1) {
            printf("Port (recommended 8000): ");
            if (scanf("%d", &port) != 1 || port < 1024 || port > 65535) { clear_input_buffer(); printf("Invalid port.\n"); continue; }
            clear_input_buffer();
            run_server(port);
        } else if (choice == 2) {
            printf("Server IPv4 address (127.0.0.1 for same computer): ");
            read_line(host, sizeof(host));
            printf("Port: ");
            if (scanf("%d", &port) != 1 || port < 1 || port > 65535) { clear_input_buffer(); printf("Invalid port.\n"); continue; }
            clear_input_buffer();
            run_client(host, port);
        } else if (choice == 3) {
            printf("\nProtocol\n");
            printf("Authentication: AUTH|username|password\n");
            printf("Signed message: TYPE|sequence|payload|HMAC-SHA256\n");
            printf("Types: PING, TELEMETRY, COMMAND\n");
            printf("Sequence numbers prevent replay. HMAC verifies integrity and authenticity.\n");
            printf("Responses use numeric status codes such as 200, 201, 403 and 409.\n");
        } else if (choice == 0) return;
        else printf("Invalid option.\n");
    }
}
