#ifndef MISSION_H
#define MISSION_H

void task1_menu(void);
void task2_menu(void);
void task3_menu(void);
void task4_menu(void);

int run_server(int port);
int run_client(const char *host, int port);

void clear_input_buffer(void);
void read_line(char *buffer, int size);

#endif
