CC = gcc
CFLAGS = -Wall -Wextra -pedantic -std=c11 -pthread -D_DEFAULT_SOURCE
LDFLAGS = -pthread -lssl -lcrypto
SOURCES = main.c task1.c task2.c task3.c task4.c server.c client.c
TARGET = mission_control

all: $(TARGET)

$(TARGET): $(SOURCES) mission.h
	$(CC) $(CFLAGS) $(SOURCES) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o metadata.tmp

run: $(TARGET)
	./$(TARGET)
