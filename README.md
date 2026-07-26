# Space Mission Control and Satellite Data System

Ubuntu C coursework application for ST5004CEM Operating Systems and Security.

## Install requirements

```bash
sudo apt update
sudo apt install build-essential libssl-dev
```

## Compile

```bash
make
```

Alternative single command:

```bash
gcc -Wall -Wextra -pedantic -std=c11 -pthread -D_DEFAULT_SOURCE \
main.c task1.c task2.c task3.c task4.c server.c client.c \
-o mission_control -lssl -lcrypto
```

## Run

```bash
./mission_control
```

## Task 3 first login

On the first run, the system creates:

- Username: `admin`
- Password: `admin123`

Use the administrator menu to create another user. Coursework demonstration data is stored locally in `mission_data/`, `users.db`, `metadata.db`, and `task3_audit.log`.

## Task 4 local test

Open two terminals in the same project folder.

Terminal 1:

```bash
./mission_control
```

Choose Task 4, start server, and use port 8000.

Terminal 2:

```bash
./mission_control
```

Choose Task 4, start client, use host `127.0.0.1` and port `8000`.

Default demonstration client credentials are built into the client and server:

- Username: `satellite1`
- Password: `orbit123`

Press Ctrl+C in the server terminal to stop the server.

## Clean generated files

```bash
make clean
rm -rf mission_data users.db metadata.db task1_mission.log task3_audit.log task4_server.log
```
