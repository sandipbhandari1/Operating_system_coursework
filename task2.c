#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "mission.h"

#define MAX_REFERENCES 100
#define MAX_FRAMES 20

typedef struct {
    int hits;
    int faults;
} PageStats;

static void print_frames(int frames[], int frame_count) {
    printf("[");
    for (int i = 0; i < frame_count; i++) {
        if (frames[i] == -1) printf(" - ");
        else printf(" %d ", frames[i]);
    }
    printf("]");
}

static int find_page(int frames[], int frame_count, int page) {
    for (int i = 0; i < frame_count; i++) {
        if (frames[i] == page) return i;
    }
    return -1;
}

static PageStats simulate_fifo(int refs[], int count, int frame_count, int detailed) {
    int frames[MAX_FRAMES];
    int pointer = 0;
    PageStats stats = {0, 0};

    for (int i = 0; i < frame_count; i++) frames[i] = -1;

    if (detailed) printf("\nFIFO page replacement\n");
    for (int i = 0; i < count; i++) {
        int hit = find_page(frames, frame_count, refs[i]) >= 0;
        if (hit) {
            stats.hits++;
        } else {
            frames[pointer] = refs[i];
            pointer = (pointer + 1) % frame_count;
            stats.faults++;
        }
        if (detailed) {
            printf("Step %2d Page %2d ", i + 1, refs[i]);
            print_frames(frames, frame_count);
            printf("  %s\n", hit ? "HIT" : "PAGE FAULT");
        }
    }
    return stats;
}

static PageStats simulate_lru(int refs[], int count, int frame_count, int detailed) {
    int frames[MAX_FRAMES];
    int last_used[MAX_FRAMES];
    PageStats stats = {0, 0};

    for (int i = 0; i < frame_count; i++) {
        frames[i] = -1;
        last_used[i] = -1;
    }

    if (detailed) printf("\nLRU page replacement\n");
    for (int i = 0; i < count; i++) {
        int pos = find_page(frames, frame_count, refs[i]);
        int hit = pos >= 0;

        if (hit) {
            stats.hits++;
            last_used[pos] = i;
        } else {
            int replace = -1;
            for (int j = 0; j < frame_count; j++) {
                if (frames[j] == -1) {
                    replace = j;
                    break;
                }
            }
            if (replace == -1) {
                int oldest = INT_MAX;
                for (int j = 0; j < frame_count; j++) {
                    if (last_used[j] < oldest) {
                        oldest = last_used[j];
                        replace = j;
                    }
                }
            }
            frames[replace] = refs[i];
            last_used[replace] = i;
            stats.faults++;
        }

        if (detailed) {
            printf("Step %2d Page %2d ", i + 1, refs[i]);
            print_frames(frames, frame_count);
            printf("  %s\n", hit ? "HIT" : "PAGE FAULT");
        }
    }
    return stats;
}

static PageStats simulate_optimal(int refs[], int count, int frame_count, int detailed) {
    int frames[MAX_FRAMES];
    PageStats stats = {0, 0};

    for (int i = 0; i < frame_count; i++) frames[i] = -1;

    if (detailed) printf("\nOptimal page replacement (innovation feature)\n");
    for (int i = 0; i < count; i++) {
        int pos = find_page(frames, frame_count, refs[i]);
        int hit = pos >= 0;

        if (hit) {
            stats.hits++;
        } else {
            int replace = -1;
            for (int j = 0; j < frame_count; j++) {
                if (frames[j] == -1) {
                    replace = j;
                    break;
                }
            }

            if (replace == -1) {
                int farthest = -1;
                for (int j = 0; j < frame_count; j++) {
                    int next = count + 1;
                    for (int k = i + 1; k < count; k++) {
                        if (refs[k] == frames[j]) {
                            next = k;
                            break;
                        }
                    }
                    if (next > farthest) {
                        farthest = next;
                        replace = j;
                    }
                }
            }
            frames[replace] = refs[i];
            stats.faults++;
        }

        if (detailed) {
            printf("Step %2d Page %2d ", i + 1, refs[i]);
            print_frames(frames, frame_count);
            printf("  %s\n", hit ? "HIT" : "PAGE FAULT");
        }
    }
    return stats;
}

static void print_stats(const char *name, PageStats s, int total) {
    double hit_ratio = total ? (double)s.hits / total * 100.0 : 0.0;
    double miss_ratio = total ? (double)s.faults / total * 100.0 : 0.0;
    printf("%-10s Hits: %2d  Faults: %2d  Hit ratio: %6.2f%%  Miss ratio: %6.2f%%\n",
           name, s.hits, s.faults, hit_ratio, miss_ratio);
}

static void run_simulation(int refs[], int count, int frames, int page_size) {
    PageStats fifo, lru, optimal;
    if (frames < 1 || frames > MAX_FRAMES || count < 1) {
        printf("Invalid simulation settings.\n");
        return;
    }

    printf("\nConfigured page size: %d KB\n", page_size);
    printf("Physical frames: %d\n", frames);
    printf("Simulated physical memory: %d KB\n", page_size * frames);

    fifo = simulate_fifo(refs, count, frames, 1);
    lru = simulate_lru(refs, count, frames, 1);
    optimal = simulate_optimal(refs, count, frames, 1);

    printf("\nPerformance summary\n");
    print_stats("FIFO", fifo, count);
    print_stats("LRU", lru, count);
    print_stats("Optimal", optimal, count);

    if (fifo.faults < lru.faults)
        printf("FIFO produced fewer faults than LRU for this workload.\n");
    else if (lru.faults < fifo.faults)
        printf("LRU produced fewer faults than FIFO for this workload.\n");
    else
        printf("FIFO and LRU produced the same number of faults.\n");
    printf("Optimal is a benchmark because it assumes knowledge of future references.\n");
}

static void built_in_test(int test_number) {
    int refs1[] = {1,2,3,4,1,2,5,1,2,3,4,5};
    int refs2[] = {7,0,1,2,0,3,0,4,2,3,0,3,2};
    if (test_number == 1)
        run_simulation(refs1, (int)(sizeof(refs1) / sizeof(refs1[0])), 3, 4);
    else
        run_simulation(refs2, (int)(sizeof(refs2) / sizeof(refs2[0])), 4, 8);
}

static void custom_test(void) {
    int refs[MAX_REFERENCES];
    int count, frames, page_size;

    printf("Number of page references (1-%d): ", MAX_REFERENCES);
    if (scanf("%d", &count) != 1 || count < 1 || count > MAX_REFERENCES) {
        clear_input_buffer();
        printf("Invalid count.\n");
        return;
    }
    printf("Enter %d page numbers: ", count);
    for (int i = 0; i < count; i++) {
        if (scanf("%d", &refs[i]) != 1 || refs[i] < 0) {
            clear_input_buffer();
            printf("Invalid page number.\n");
            return;
        }
    }
    printf("Number of frames (1-%d): ", MAX_FRAMES);
    if (scanf("%d", &frames) != 1 || frames < 1 || frames > MAX_FRAMES) {
        clear_input_buffer();
        printf("Invalid frame count.\n");
        return;
    }
    printf("Page size in KB: ");
    if (scanf("%d", &page_size) != 1 || page_size <= 0) {
        clear_input_buffer();
        printf("Invalid page size.\n");
        return;
    }
    clear_input_buffer();
    run_simulation(refs, count, frames, page_size);
}

void task2_menu(void) {
    int choice;
    while (1) {
        printf("\nTask 2 - Satellite Virtual Memory Simulator\n");
        printf("1. Run prepared test case 1\n");
        printf("2. Run prepared test case 2\n");
        printf("3. Enter a custom reference string\n");
        printf("0. Return to main menu\n");
        printf("Select an option: ");

        if (scanf("%d", &choice) != 1) {
            clear_input_buffer();
            printf("Invalid input.\n");
            continue;
        }
        clear_input_buffer();

        if (choice == 1) built_in_test(1);
        else if (choice == 2) built_in_test(2);
        else if (choice == 3) custom_test();
        else if (choice == 0) return;
        else printf("Invalid option.\n");
    }
}
