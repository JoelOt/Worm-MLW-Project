#include "state_manager.h"
#include <string.h>

#define MAX_INFECTED 50
#define MAX_IP_LEN 16

// In-memory state tracking for infected IPs
// Prevents duplicate infections and infinite propagation loops
static char infected_ips[MAX_INFECTED][MAX_IP_LEN];
static int infected_count = 0;

void init_state(void) {
    infected_count = 0;
    memset(infected_ips, 0, sizeof(infected_ips));
}

/**
 * Check if IP address is already marked as infected
 * Returns 1 if infected, 0 otherwise
 */
int is_infected(const char* ip) {
    for (int i = 0; i < infected_count; i++) {
        if (strcmp(infected_ips[i], ip) == 0) {
            return 1;
        }
    }
    return 0;
}

/**
 * Mark IP address as infected
 * Prevents duplicate entries and respects MAX_INFECTED limit
 */
void mark_infected(const char* ip) {
    // Only add if not already infected and within limit
    if (!is_infected(ip) && infected_count < MAX_INFECTED) {
        strncpy(infected_ips[infected_count], ip, MAX_IP_LEN - 1);
        infected_ips[infected_count][MAX_IP_LEN - 1] = '\0';
        infected_count++;
    }
}

void clear_state(void) {
    init_state();
}

