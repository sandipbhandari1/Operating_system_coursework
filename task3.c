#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <termios.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "mission.h"

#define USER_DB "users.db"
#define META_DB "metadata.db"
#define AUDIT_LOG "task3_audit.log"
#define DATA_DIR "mission_data"
#define MAX_LINE 2048
#define SALT_SIZE 16
#define HASH_SIZE 32
#define KEY_SIZE 32
#define GCM_IV_SIZE 12
#define GCM_TAG_SIZE 16
#define PBKDF2_ITERATIONS 120000

typedef struct {
    char username[32];
    char role[16];
    int logged_in;
} Session;

typedef struct {
    char filename[80];
    char owner[32];
    char group[16];
    char permissions[10];
    int encrypted;
} FileMeta;

static Session session = {{0}, {0}, 0};

static void bytes_to_hex(const unsigned char *bytes, int length, char *hex) {
    for (int i = 0; i < length; i++) sprintf(hex + i * 2, "%02x", bytes[i]);
    hex[length * 2] = '\0';
}

static int hex_to_bytes(const char *hex, unsigned char *bytes, int expected) {
    if ((int)strlen(hex) != expected * 2) return 0;
    for (int i = 0; i < expected; i++) {
        unsigned int value;
        if (sscanf(hex + i * 2, "%2x", &value) != 1) return 0;
        bytes[i] = (unsigned char)value;
    }
    return 1;
}

static void read_password(char *password, int size) {
    struct termios old_settings, new_settings;
    if (tcgetattr(STDIN_FILENO, &old_settings) != 0) {
        read_line(password, size);
        return;
    }
    new_settings = old_settings;
    new_settings.c_lflag &= (tcflag_t)~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_settings);
    read_line(password, size);
    tcsetattr(STDIN_FILENO, TCSANOW, &old_settings);
    printf("\n");
}

static void sha256_text(const char *text, char output_hex[65]) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)text, strlen(text), digest);
    bytes_to_hex(digest, SHA256_DIGEST_LENGTH, output_hex);
}

static void audit_event(const char *action, const char *target, const char *result) {
    FILE *fp;
    char previous_hash[65] = "GENESIS";
    char line[MAX_LINE], content[MAX_LINE], new_hash[65];
    time_t now = time(NULL);
    struct tm local_tm;
    char stamp[32];

    fp = fopen(AUDIT_LOG, "r");
    if (fp != NULL) {
        while (fgets(line, sizeof(line), fp) != NULL) {
            char *last = strrchr(line, '|');
            if (last != NULL) {
                last++;
                while (*last == ' ') last++;
                last[strcspn(last, "\r\n")] = '\0';
                strncpy(previous_hash, last, sizeof(previous_hash) - 1);
                previous_hash[sizeof(previous_hash) - 1] = '\0';
            }
        }
        fclose(fp);
    }

    localtime_r(&now, &local_tm);
    strftime(stamp, sizeof(stamp), "%Y-%m-%d %H:%M:%S", &local_tm);
    snprintf(content, sizeof(content), "%s|%s|%s|%s|%s|%s",
             stamp,
             session.logged_in ? session.username : "anonymous",
             action,
             target ? target : "-",
             result,
             previous_hash);
    sha256_text(content, new_hash);

    fp = fopen(AUDIT_LOG, "a");
    if (fp != NULL) {
        fprintf(fp, "%s | user=%s | action=%s | target=%s | result=%s | prev=%s | %s\n",
                stamp,
                session.logged_in ? session.username : "anonymous",
                action,
                target ? target : "-",
                result,
                previous_hash,
                new_hash);
        fclose(fp);
    }
}

static int valid_name(const char *name) {
    size_t len = strlen(name);
    if (len == 0 || len >= 70 || strstr(name, "..") != NULL) return 0;
    for (size_t i = 0; i < len; i++) {
        if (!(isalnum((unsigned char)name[i]) || name[i] == '_' || name[i] == '-' || name[i] == '.')) return 0;
    }
    return 1;
}

static void build_path(const char *filename, char *path, size_t path_size) {
    snprintf(path, path_size, "%s/%s", DATA_DIR, filename);
}

static int derive_password_hash(const char *password, const unsigned char *salt, unsigned char *hash) {
    return PKCS5_PBKDF2_HMAC(password, (int)strlen(password), salt, SALT_SIZE,
                             PBKDF2_ITERATIONS, EVP_sha256(), HASH_SIZE, hash);
}

static int create_user_record(const char *username, const char *password, const char *role) {
    FILE *fp;
    unsigned char salt[SALT_SIZE], hash[HASH_SIZE];
    char salt_hex[SALT_SIZE * 2 + 1], hash_hex[HASH_SIZE * 2 + 1];

    if (RAND_bytes(salt, sizeof(salt)) != 1 || !derive_password_hash(password, salt, hash)) return 0;
    bytes_to_hex(salt, SALT_SIZE, salt_hex);
    bytes_to_hex(hash, HASH_SIZE, hash_hex);

    fp = fopen(USER_DB, "a");
    if (fp == NULL) return 0;
    fprintf(fp, "%s|%s|%s|%s\n", username, salt_hex, hash_hex, role);
    fclose(fp);
    chmod(USER_DB, S_IRUSR | S_IWUSR);
    return 1;
}

static int user_exists(const char *username) {
    FILE *fp = fopen(USER_DB, "r");
    char line[MAX_LINE], name[32];
    if (fp == NULL) return 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        if (sscanf(line, "%31[^|]", name) == 1 && strcmp(name, username) == 0) {
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

static void initialize_security_files(void) {
    struct stat st;
    if (stat(DATA_DIR, &st) != 0) mkdir(DATA_DIR, S_IRWXU);
    if (access(USER_DB, F_OK) != 0) {
        create_user_record("admin", "admin123", "admin");
        printf("First run: default administrator created.\n");
        printf("Username: admin   Password: admin123\n");
        printf("Create another user and protect this account for final demonstration.\n");
    }
}

static int authenticate(const char *username, const char *password, char *role_out) {
    FILE *fp = fopen(USER_DB, "r");
    char line[MAX_LINE];
    if (fp == NULL) return 0;

    while (fgets(line, sizeof(line), fp) != NULL) {
        char name[32], salt_hex[65], hash_hex[129], role[16];
        unsigned char salt[SALT_SIZE], expected[HASH_SIZE], actual[HASH_SIZE];
        if (sscanf(line, "%31[^|]|%64[^|]|%128[^|]|%15[^\n]", name, salt_hex, hash_hex, role) == 4 &&
            strcmp(name, username) == 0 &&
            hex_to_bytes(salt_hex, salt, SALT_SIZE) &&
            hex_to_bytes(hash_hex, expected, HASH_SIZE) &&
            derive_password_hash(password, salt, actual) &&
            CRYPTO_memcmp(expected, actual, HASH_SIZE) == 0) {
            strncpy(role_out, role, 15);
            role_out[15] = '\0';
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

static int login_user(void) {
    char username[32], password[128], role[16];
    int attempts = 0;

    while (attempts < 3) {
        printf("Username: ");
        read_line(username, sizeof(username));
        printf("Password: ");
        read_password(password, sizeof(password));

        if (authenticate(username, password, role)) {
            strncpy(session.username, username, sizeof(session.username) - 1);
            strncpy(session.role, role, sizeof(session.role) - 1);
            session.logged_in = 1;
            memset(password, 0, sizeof(password));
            audit_event("LOGIN", "-", "SUCCESS");
            printf("Login successful. Role: %s\n", session.role);
            return 1;
        }
        memset(password, 0, sizeof(password));
        attempts++;
        audit_event("LOGIN", username, "FAILED");
        printf("Authentication failed. Attempts remaining: %d\n", 3 - attempts);
    }
    printf("Login temporarily blocked for this session.\n");
    return 0;
}

static int load_meta(const char *filename, FileMeta *meta) {
    FILE *fp = fopen(META_DB, "r");
    char line[MAX_LINE];
    if (fp == NULL) return 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        FileMeta temp;
        if (sscanf(line, "%79[^|]|%31[^|]|%15[^|]|%9[^|]|%d",
                   temp.filename, temp.owner, temp.group, temp.permissions, &temp.encrypted) == 5 &&
            strcmp(temp.filename, filename) == 0) {
            *meta = temp;
            fclose(fp);
            return 1;
        }
    }
    fclose(fp);
    return 0;
}

static int save_meta(const FileMeta *meta, int replace) {
    FILE *in = fopen(META_DB, "r");
    FILE *out = fopen("metadata.tmp", "w");
    char line[MAX_LINE];
    int found = 0;
    if (out == NULL) return 0;

    if (in != NULL) {
        while (fgets(line, sizeof(line), in) != NULL) {
            char name[80];
            if (sscanf(line, "%79[^|]", name) == 1 && strcmp(name, meta->filename) == 0) {
                found = 1;
                if (replace) fprintf(out, "%s|%s|%s|%s|%d\n", meta->filename, meta->owner, meta->group, meta->permissions, meta->encrypted);
            } else {
                fputs(line, out);
            }
        }
        fclose(in);
    }
    if (!found && !replace) fprintf(out, "%s|%s|%s|%s|%d\n", meta->filename, meta->owner, meta->group, meta->permissions, meta->encrypted);
    fclose(out);
    if (rename("metadata.tmp", META_DB) != 0) return 0;
    chmod(META_DB, S_IRUSR | S_IWUSR);
    return 1;
}


static int delete_meta_record(const char *filename) {
    FILE *in = fopen(META_DB, "r");
    FILE *out = fopen("metadata.tmp", "w");
    char line[MAX_LINE];
    int found = 0;
    if (out == NULL) return 0;
    if (in != NULL) {
        while (fgets(line, sizeof(line), in) != NULL) {
            char name[80];
            if (sscanf(line, "%79[^|]", name) == 1 && strcmp(name, filename) == 0) {
                found = 1;
                continue;
            }
            fputs(line, out);
        }
        fclose(in);
    }
    fclose(out);
    if (rename("metadata.tmp", META_DB) != 0) return 0;
    chmod(META_DB, S_IRUSR | S_IWUSR);
    return found;
}

static int permission_allowed(const FileMeta *meta, char operation) {
    int offset;
    if (strcmp(session.role, "admin") == 0) return 1;
    if (strcmp(session.username, meta->owner) == 0) offset = 0;
    else if (strcmp(session.role, meta->group) == 0) offset = 3;
    else offset = 6;

    if (operation == 'r') return meta->permissions[offset] == 'r';
    if (operation == 'w') return meta->permissions[offset + 1] == 'w';
    if (operation == 'x') return meta->permissions[offset + 2] == 'x';
    return 0;
}

static int derive_file_key(const char *password, const unsigned char salt[SALT_SIZE], unsigned char key[KEY_SIZE]) {
    return PKCS5_PBKDF2_HMAC(password, (int)strlen(password), salt, SALT_SIZE,
                             PBKDF2_ITERATIONS, EVP_sha256(), KEY_SIZE, key);
}

static int encrypt_buffer(const unsigned char *plain, int plain_len, const char *password,
                          unsigned char **output, int *output_len) {
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char salt[SALT_SIZE], iv[GCM_IV_SIZE], key[KEY_SIZE], tag[GCM_TAG_SIZE];
    unsigned char *cipher = NULL;
    int len = 0, cipher_len = 0;

    if (RAND_bytes(salt, sizeof(salt)) != 1 || RAND_bytes(iv, sizeof(iv)) != 1 ||
        !derive_file_key(password, salt, key)) return 0;

    cipher = malloc((size_t)plain_len + 64);
    ctx = EVP_CIPHER_CTX_new();
    if (cipher == NULL || ctx == NULL) goto fail;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto fail;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, NULL) != 1) goto fail;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto fail;
    if (EVP_EncryptUpdate(ctx, cipher, &len, plain, plain_len) != 1) goto fail;
    cipher_len = len;
    if (EVP_EncryptFinal_ex(ctx, cipher + cipher_len, &len) != 1) goto fail;
    cipher_len += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag) != 1) goto fail;

    *output_len = 4 + SALT_SIZE + GCM_IV_SIZE + GCM_TAG_SIZE + cipher_len;
    *output = malloc((size_t)*output_len);
    if (*output == NULL) goto fail;
    memcpy(*output, "SMC1", 4);
    memcpy(*output + 4, salt, SALT_SIZE);
    memcpy(*output + 4 + SALT_SIZE, iv, GCM_IV_SIZE);
    memcpy(*output + 4 + SALT_SIZE + GCM_IV_SIZE, tag, GCM_TAG_SIZE);
    memcpy(*output + 4 + SALT_SIZE + GCM_IV_SIZE + GCM_TAG_SIZE, cipher, (size_t)cipher_len);

    OPENSSL_cleanse(key, sizeof(key));
    free(cipher);
    EVP_CIPHER_CTX_free(ctx);
    return 1;

fail:
    OPENSSL_cleanse(key, sizeof(key));
    free(cipher);
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

static int decrypt_buffer(const unsigned char *input, int input_len, const char *password,
                          unsigned char **plain, int *plain_len) {
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char key[KEY_SIZE];
    int header = 4 + SALT_SIZE + GCM_IV_SIZE + GCM_TAG_SIZE;
    int len = 0, out_len = 0;

    if (input_len < header || memcmp(input, "SMC1", 4) != 0) return 0;
    const unsigned char *salt = input + 4;
    const unsigned char *iv = salt + SALT_SIZE;
    const unsigned char *tag = iv + GCM_IV_SIZE;
    const unsigned char *cipher = tag + GCM_TAG_SIZE;
    int cipher_len = input_len - header;

    if (!derive_file_key(password, salt, key)) return 0;
    *plain = malloc((size_t)cipher_len + 1);
    ctx = EVP_CIPHER_CTX_new();
    if (*plain == NULL || ctx == NULL) goto fail;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto fail;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, NULL) != 1) goto fail;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) goto fail;
    if (EVP_DecryptUpdate(ctx, *plain, &len, cipher, cipher_len) != 1) goto fail;
    out_len = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, (void *)tag) != 1) goto fail;
    if (EVP_DecryptFinal_ex(ctx, *plain + out_len, &len) != 1) goto fail;
    out_len += len;
    (*plain)[out_len] = '\0';
    *plain_len = out_len;
    OPENSSL_cleanse(key, sizeof(key));
    EVP_CIPHER_CTX_free(ctx);
    return 1;

fail:
    OPENSSL_cleanse(key, sizeof(key));
    free(*plain);
    *plain = NULL;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

static int write_file_data(const char *path, const unsigned char *data, int length) {
    FILE *fp = fopen(path, "wb");
    if (fp == NULL) return 0;
    if ((int)fwrite(data, 1, (size_t)length, fp) != length) {
        fclose(fp);
        return 0;
    }
    fclose(fp);
    chmod(path, S_IRUSR | S_IWUSR);
    return 1;
}

static unsigned char *read_file_data(const char *path, int *length) {
    FILE *fp = fopen(path, "rb");
    long size;
    unsigned char *data;
    if (fp == NULL) return NULL;
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    rewind(fp);
    if (size < 0 || size > 1024 * 1024) { fclose(fp); return NULL; }
    data = malloc((size_t)size + 1);
    if (data == NULL) { fclose(fp); return NULL; }
    *length = (int)fread(data, 1, (size_t)size, fp);
    data[*length] = '\0';
    fclose(fp);
    return data;
}

static void create_mission_file(void) {
    FileMeta meta;
    char content[1024], path[160], password[128];
    unsigned char *output = NULL;
    int output_len;

    printf("File name: ");
    read_line(meta.filename, sizeof(meta.filename));
    if (!valid_name(meta.filename) || load_meta(meta.filename, &meta)) {
        printf("Invalid name or file already exists.\n");
        return;
    }
    printf("Initial content (maximum 1000 characters): ");
    read_line(content, sizeof(content));
    printf("Encrypt sensitive file? (1=yes, 0=no): ");
    if (scanf("%d", &meta.encrypted) != 1 || (meta.encrypted != 0 && meta.encrypted != 1)) {
        clear_input_buffer(); printf("Invalid choice.\n"); return;
    }
    clear_input_buffer();

    strncpy(meta.owner, session.username, sizeof(meta.owner) - 1);
    strncpy(meta.group, session.role, sizeof(meta.group) - 1);
    strcpy(meta.permissions, "rw-r-----");
    build_path(meta.filename, path, sizeof(path));

    if (meta.encrypted) {
        printf("Encryption password: ");
        read_password(password, sizeof(password));
        if (strlen(password) < 8 || !encrypt_buffer((unsigned char *)content, (int)strlen(content), password, &output, &output_len)) {
            printf("Encryption failed. Use at least 8 characters.\n");
            memset(password, 0, sizeof(password));
            return;
        }
        if (!write_file_data(path, output, output_len)) { printf("File write failed.\n"); free(output); return; }
        free(output);
        memset(password, 0, sizeof(password));
    } else if (!write_file_data(path, (unsigned char *)content, (int)strlen(content))) {
        printf("File write failed.\n"); return;
    }

    if (!save_meta(&meta, 0)) { remove(path); printf("Metadata write failed.\n"); return; }
    audit_event("CREATE", meta.filename, "SUCCESS");
    printf("Mission file created with permission %s.\n", meta.permissions);
}

static void read_mission_file(void) {
    char filename[80], path[160], password[128];
    FileMeta meta;
    unsigned char *data, *plain = NULL;
    int length, plain_len;

    printf("File name: ");
    read_line(filename, sizeof(filename));
    if (!valid_name(filename) || !load_meta(filename, &meta)) { printf("File not found.\n"); return; }
    if (!permission_allowed(&meta, 'r')) { audit_event("READ", filename, "DENIED"); printf("Read permission denied.\n"); return; }
    build_path(filename, path, sizeof(path));
    data = read_file_data(path, &length);
    if (data == NULL) { printf("Could not read file.\n"); return; }

    if (meta.encrypted) {
        printf("Decryption password: ");
        read_password(password, sizeof(password));
        if (!decrypt_buffer(data, length, password, &plain, &plain_len)) {
            audit_event("DECRYPT", filename, "FAILED");
            printf("Decryption failed: wrong password or modified ciphertext.\n");
            free(data); memset(password, 0, sizeof(password)); return;
        }
        printf("\nContent:\n%.*s\n", plain_len, plain);
        OPENSSL_cleanse(plain, (size_t)plain_len);
        free(plain);
        memset(password, 0, sizeof(password));
    } else {
        printf("\nContent:\n%.*s\n", length, data);
    }
    free(data);
    audit_event("READ", filename, "SUCCESS");
}

static void overwrite_mission_file(void) {
    char filename[80], content[1024], path[160], password[128];
    FileMeta meta;
    unsigned char *output = NULL;
    int output_len;

    printf("File name: "); read_line(filename, sizeof(filename));
    if (!valid_name(filename) || !load_meta(filename, &meta)) { printf("File not found.\n"); return; }
    if (!permission_allowed(&meta, 'w')) { audit_event("WRITE", filename, "DENIED"); printf("Write permission denied.\n"); return; }
    printf("New content: "); read_line(content, sizeof(content));
    build_path(filename, path, sizeof(path));

    if (meta.encrypted) {
        printf("Encryption password: "); read_password(password, sizeof(password));
        if (strlen(password) < 8 || !encrypt_buffer((unsigned char *)content, (int)strlen(content), password, &output, &output_len)) {
            printf("Encryption failed.\n"); memset(password, 0, sizeof(password)); return;
        }
        if (!write_file_data(path, output, output_len)) { printf("Write failed.\n"); free(output); return; }
        free(output); memset(password, 0, sizeof(password));
    } else if (!write_file_data(path, (unsigned char *)content, (int)strlen(content))) {
        printf("Write failed.\n"); return;
    }
    audit_event("WRITE", filename, "SUCCESS");
    printf("File updated.\n");
}

static void delete_mission_file(void) {
    char filename[80], path[160];
    FileMeta meta;
    printf("File name: "); read_line(filename, sizeof(filename));
    if (!valid_name(filename) || !load_meta(filename, &meta)) { printf("File not found.\n"); return; }
    if (!permission_allowed(&meta, 'w')) { audit_event("DELETE", filename, "DENIED"); printf("Delete permission denied.\n"); return; }
    build_path(filename, path, sizeof(path));
    if (remove(path) != 0 || !delete_meta_record(filename)) { printf("Delete failed.\n"); return; }
    audit_event("DELETE", filename, "SUCCESS");
    printf("File deleted.\n");
}

static void list_mission_files(void) {
    FILE *fp = fopen(META_DB, "r");
    char line[MAX_LINE];
    printf("\n%-22s %-14s %-12s %-10s %s\n", "File", "Owner", "Group", "Permission", "Encrypted");
    if (fp == NULL) { printf("No mission files.\n"); return; }
    while (fgets(line, sizeof(line), fp) != NULL) {
        FileMeta m;
        if (sscanf(line, "%79[^|]|%31[^|]|%15[^|]|%9[^|]|%d", m.filename, m.owner, m.group, m.permissions, &m.encrypted) == 5)
            printf("%-22s %-14s %-12s %-10s %s\n", m.filename, m.owner, m.group, m.permissions, m.encrypted ? "Yes" : "No");
    }
    fclose(fp);
    audit_event("LIST", "-", "SUCCESS");
}

static int valid_permission(const char *p) {
    if (strlen(p) != 9) return 0;
    for (int i = 0; i < 9; i++) {
        char expected = "rwx"[i % 3];
        if (p[i] != expected && p[i] != '-') return 0;
    }
    return 1;
}

static void change_permissions(void) {
    char filename[80], permission[10];
    FileMeta meta;
    printf("File name: "); read_line(filename, sizeof(filename));
    if (!load_meta(filename, &meta)) { printf("File not found.\n"); return; }
    if (strcmp(session.role, "admin") != 0 && strcmp(session.username, meta.owner) != 0) {
        audit_event("CHMOD", filename, "DENIED"); printf("Only owner or admin can change permissions.\n"); return;
    }
    printf("Permission (example rw-r-----): "); read_line(permission, sizeof(permission));
    if (!valid_permission(permission)) { printf("Invalid permission format.\n"); return; }
    strcpy(meta.permissions, permission);
    if (!save_meta(&meta, 1)) { printf("Metadata update failed.\n"); return; }
    audit_event("CHMOD", filename, "SUCCESS");
    printf("Permission updated.\n");
}

static void create_user(void) {
    char username[32], password[128], role[16];
    if (strcmp(session.role, "admin") != 0) { printf("Administrator access required.\n"); return; }
    printf("New username: "); read_line(username, sizeof(username));
    if (!valid_name(username) || user_exists(username)) { printf("Invalid or duplicate username.\n"); return; }
    printf("Role (admin/controller/scientist/operator): "); read_line(role, sizeof(role));
    if (strcmp(role, "admin") && strcmp(role, "controller") && strcmp(role, "scientist") && strcmp(role, "operator")) {
        printf("Invalid role.\n"); return;
    }
    printf("Password (minimum 8 characters): "); read_password(password, sizeof(password));
    if (strlen(password) < 8 || !create_user_record(username, password, role)) { printf("User creation failed.\n"); memset(password, 0, sizeof(password)); return; }
    memset(password, 0, sizeof(password));
    audit_event("CREATE_USER", username, "SUCCESS");
    printf("User created.\n");
}

static void show_audit_log(void) {
    FILE *fp;
    char line[MAX_LINE];
    if (strcmp(session.role, "admin") != 0) { printf("Administrator access required.\n"); return; }
    fp = fopen(AUDIT_LOG, "r");
    if (fp == NULL) { printf("No audit entries.\n"); return; }
    while (fgets(line, sizeof(line), fp) != NULL) fputs(line, stdout);
    fclose(fp);
}

void task3_menu(void) {
    int choice;
    initialize_security_files();
    if (!login_user()) return;

    while (session.logged_in) {
        printf("\nTask 3 - Secure Mission File Management (%s: %s)\n", session.username, session.role);
        printf("1. Create file\n2. Read file\n3. Write/overwrite file\n4. Delete file\n");
        printf("5. List files\n6. Change file permissions\n7. Create user (admin)\n8. View audit log (admin)\n0. Logout\n");
        printf("Select an option: ");
        if (scanf("%d", &choice) != 1) { clear_input_buffer(); printf("Invalid input.\n"); continue; }
        clear_input_buffer();

        if (choice == 1) create_mission_file();
        else if (choice == 2) read_mission_file();
        else if (choice == 3) overwrite_mission_file();
        else if (choice == 4) delete_mission_file();
        else if (choice == 5) list_mission_files();
        else if (choice == 6) change_permissions();
        else if (choice == 7) create_user();
        else if (choice == 8) show_audit_log();
        else if (choice == 0) {
            audit_event("LOGOUT", "-", "SUCCESS");
            memset(&session, 0, sizeof(session));
            printf("Logged out.\n");
        } else printf("Invalid option.\n");
    }
}
