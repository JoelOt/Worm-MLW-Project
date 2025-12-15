#ifndef CVE_SSH_PROPAGATION_H
#define CVE_SSH_PROPAGATION_H

#include "handler_registry.h"

cve_scan_result_t cve_ssh_propagation_scan(const char* target_ip);
int cve_ssh_propagation_execute(const char* target_ip);

// Helper functions to get discovered data
void get_discovered_networks(char** networks, int* count);
int get_ssh_key_count(void);

// Get vulnerable hosts discovered during scan phase
// Returns number of vulnerable hosts found
int get_vulnerable_hosts(char** hosts, int* count, int max_hosts);

#endif // CVE_SSH_PROPAGATION_H

