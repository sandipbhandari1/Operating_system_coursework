#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mission.h"

void clear_input_buffer(void) {
    int c;
    while ((c = getchar()) != '\n' && c != EOF) { }
}

void read_line(char *buffer, int size) {
    if (fgets(buffer, size, stdin) != NULL) {
        buffer[strcspn(buffer, "\n")] = '\0';
    }
}

int main(void) {
    int choice;

    while (1) {
        printf("\nSpace Mission Control and Satellite Data System\n");
        printf("1. Task 1 - Process Management and Threading\n");
        printf("2. Task 2 - Memory Management Simulation\n");
        printf("3. Task 3 - Secure File Management System\n");
        printf("4. Task 4 - Network Programming and IPC\n");
        printf("0. Exit\n");
        printf("Select an option: ");

        if (scanf("%d", &choice) != 1) {
            clear_input_buffer();
            printf("Invalid input.\n");
            continue;
        }
        clear_input_buffer();

        switch (choice) {
            case 1: task1_menu(); break;
            case 2: task2_menu(); break;
            case 3: task3_menu(); break;
            case 4: task4_menu(); break;
            case 0:
                printf("Mission Control application closed.\n");
                return 0;
            default:
                printf("Invalid option.\n");
        }
    }
}
