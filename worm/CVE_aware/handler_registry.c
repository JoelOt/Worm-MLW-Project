#include "handler_registry.h"
#include "cve_2014_6271.h"  // Include CVE handler files
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Handler registry (hardcoded for now)
static cve_handler_config_t handlers[MAX_CVE_HANDLERS];
static int num_handlers = 0;

// Initialize handler registry
void init_handler_registry(void) {
    num_handlers = 0;
    
    // Register CVE-2014-6271 (Shellshock)
    handlers[0].cve_id = CVE_2014_6271;
    handlers[0].scan_func = cve_2014_6271_scan;      // C function pointer
    handlers[0].exec_func = cve_2014_6271_execute;   // C function pointer
    handlers[0].priority_order = 1;
    num_handlers = 1;
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
    
    // Call C function directly (no external processes, no temp files)
    result = handler->scan_func(target_ip);
    result.cve_id = handler->cve_id;
    
    return result;
}

// Call execution handler (Phase 3)
int call_execution_handler(cve_handler_config_t* handler, const char* target_ip) {
    if (!handler || !handler->exec_func) {
        return 0;
    }
    
    // Call C function directly (no external processes, no temp files)
    return handler->exec_func(target_ip);
}

// Get all handlers for scanning
cve_result_vector_t scan_all_handlers(const char* target_ip) {
    cve_result_vector_t vector = {0};
    
    for (int i = 0; i < num_handlers; i++) {
        if (vector.count < MAX_CVE_HANDLERS) {
            vector.results[vector.count] = call_scan_handler(&handlers[i], target_ip);
            vector.count++;
        }
    }
    
    return vector;
}

