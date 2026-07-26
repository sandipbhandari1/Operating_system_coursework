#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>
#include "mission.h"

static pthread_mutex_t power_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static sem_t antenna_sem;
static int available_power = 100;

static void mission_log(const char *message) {
    FILE *fp;
    time_t now = time(NULL);
    struct tm local_tm;
    char stamp[32];

    localtime_r(&now, &local_tm);
    strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &local_tm);

    pthread_mutex_lock(&log_mutex);
    fp = fopen("task1_mission.log", "a");
    if (fp != NULL) {
        fprintf(fp, "%s | %s\n", stamp, message);
        fclose(fp);
    }
    pthread_mutex_unlock(&log_mutex);
}

static int use_power(const char *task, int amount) {
    int success = 0;
    pthread_mutex_lock(&power_mutex);
    if (available_power >= amount) {
        available_power -= amount;
        printf("%-23s used %d units. Remaining power: %d\n",
               task, amount, available_power);
        success = 1;
    } else {
        printf("%-23s could not obtain %d power units.\n", task, amount);
    }
    pthread_mutex_unlock(&power_mutex);
    return success;
}

static void return_power(const char *task, int amount) {
    pthread_mutex_lock(&power_mutex);
    available_power += amount;
    if (available_power > 100) {
        available_power = 100;
    }
    printf("%-23s returned %d units. Remaining power: %d\n",
           task, amount, available_power);
    pthread_mutex_unlock(&power_mutex);
}

static void *telemetry_thread(void *arg) {
    (void)arg;
    mission_log("Telemetry thread started");
    for (int i = 1; i <= 4; i++) {
        if (use_power("Telemetry processor", 8)) {
            printf("Telemetry processor     decoded packet %d.\n", i);
            usleep(180000);
            return_power("Telemetry processor", 8);
        }
        usleep(100000);
    }
    mission_log("Telemetry thread completed");
    return NULL;
}

static void *navigation_thread(void *arg) {
    (void)arg;
    mission_log("Navigation thread started");
    for (int i = 1; i <= 4; i++) {
        if (use_power("Navigation calculator", 12)) {
            printf("Navigation calculator  calculated orbit segment %d.\n", i);
            usleep(220000);
            return_power("Navigation calculator", 12);
        }
        usleep(120000);
    }
    mission_log("Navigation thread completed");
    return NULL;
}

static void *communication_thread(void *arg) {
    (void)arg;
    mission_log("Communication thread started");
    for (int i = 1; i <= 4; i++) {
        printf("Communication system    waiting for antenna.\n");
        sem_wait(&antenna_sem);
        if (use_power("Communication system", 15)) {
            printf("Communication system    transmitted message %d.\n", i);
            usleep(250000);
            return_power("Communication system", 15);
        }
        sem_post(&antenna_sem);
        usleep(130000);
    }
    mission_log("Communication thread completed");
    return NULL;
}

static void run_threads(void) {
    pthread_t telemetry, navigation, communication;
    available_power = 100;
    sem_init(&antenna_sem, 0, 1);

    printf("\nStarting three concurrent mission threads...\n\n");
    if (pthread_create(&telemetry, NULL, telemetry_thread, NULL) != 0 ||
        pthread_create(&navigation, NULL, navigation_thread, NULL) != 0 ||
        pthread_create(&communication, NULL, communication_thread, NULL) != 0) {
        printf("Thread creation failed.\n");
        sem_destroy(&antenna_sem);
        return;
    }

    pthread_join(telemetry, NULL);
    pthread_join(navigation, NULL);
    pthread_join(communication, NULL);
    sem_destroy(&antenna_sem);

    printf("\nAll mission threads completed. Final power: %d\n", available_power);
    printf("Thread events were written to task1_mission.log.\n");
}

typedef struct {
    char name[30];
    int burst;
    int remaining;
    int completion;
    int waiting;
    int turnaround;
} MissionProcess;

static void round_robin(void) {
    MissionProcess p[] = {
        {"Telemetry Analysis", 7, 7, 0, 0, 0},
        {"Orbit Calculation", 5, 5, 0, 0, 0},
        {"Image Compression", 9, 9, 0, 0, 0},
        {"Command Uplink", 4, 4, 0, 0, 0}
    };
    const int count = 4;
    int quantum, time = 0, finished = 0;
    double total_wait = 0.0, total_turnaround = 0.0;

    printf("Enter time quantum (recommended 2 or 3): ");
    if (scanf("%d", &quantum) != 1 || quantum <= 0) {
        clear_input_buffer();
        printf("Invalid quantum.\n");
        return;
    }
    clear_input_buffer();

    printf("\nRound-robin execution timeline\n");
    while (finished < count) {
        for (int i = 0; i < count; i++) {
            if (p[i].remaining > 0) {
                int slice = p[i].remaining < quantum ? p[i].remaining : quantum;
                printf("Time %2d-%2d: %s\n", time, time + slice, p[i].name);
                time += slice;
                p[i].remaining -= slice;

                if (p[i].remaining == 0) {
                    p[i].completion = time;
                    p[i].turnaround = p[i].completion;
                    p[i].waiting = p[i].turnaround - p[i].burst;
                    finished++;
                }
            }
        }
    }

    printf("\n%-22s %7s %10s %10s\n", "Process", "Burst", "Waiting", "Turnaround");
    for (int i = 0; i < count; i++) {
        printf("%-22s %7d %10d %10d\n",
               p[i].name, p[i].burst, p[i].waiting, p[i].turnaround);
        total_wait += p[i].waiting;
        total_turnaround += p[i].turnaround;
    }
    printf("Average waiting time: %.2f\n", total_wait / count);
    printf("Average turnaround time: %.2f\n", total_turnaround / count);
}

static void process_creation_demo(void) {
    pid_t pid = fork();

    if (pid < 0) {
        perror("fork");
        return;
    }

    if (pid == 0) {
        printf("Child process: Satellite diagnostic process running. PID=%d, Parent PID=%d\n",
               getpid(), getppid());
        sleep(1);
        printf("Child process: Diagnostic completed successfully.\n");
        _exit(0);
    }

    printf("Parent process: Mission Control created child PID %d.\n", pid);
    waitpid(pid, NULL, 0);
    printf("Parent process: Child completed and was collected with waitpid().\n");
}

static void deadlock_explanation(void) {
    printf("\nDeadlock prevention used in this task\n");
    printf("1. Shared power is protected by one mutex.\n");
    printf("2. A thread releases the power mutex before requesting other work.\n");
    printf("3. The antenna semaphore is always released after transmission.\n");
    printf("4. No circular lock dependency exists.\n");
    printf("5. Main waits for all threads before destroying synchronization objects.\n");
    printf("This prevents race conditions, circular wait and resource leakage.\n");
}

void task1_menu(void) {
    int choice;
    while (1) {
        printf("\nTask 1 - Process Management and Threading\n");
        printf("1. Run concurrent mission threads\n");
        printf("2. Run round-robin scheduler\n");
        printf("3. Demonstrate process creation\n");
        printf("4. Explain race-condition and deadlock prevention\n");
        printf("0. Return to main menu\n");
        printf("Select an option: ");

        if (scanf("%d", &choice) != 1) {
            clear_input_buffer();
            printf("Invalid input.\n");
            continue;
        }
        clear_input_buffer();

        if (choice == 1) run_threads();
        else if (choice == 2) round_robin();
        else if (choice == 3) process_creation_demo();
        else if (choice == 4) deadlock_explanation();
        else if (choice == 0) return;
        else printf("Invalid option.\n");
    }
}
