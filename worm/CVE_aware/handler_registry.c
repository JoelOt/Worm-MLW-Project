#include "handler_registry.h"
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
    
    // Register handlers (empty for now - handlers will be added when scripts are created)
    // Example structure:
    // handlers[0].cve_id = CVE_2014_6271;
    // handlers[0].scan_script_path = "scans/cve-2014-6271-scan.sh";
    // handlers[0].execution_script_path = "executions/cve-2014-6271.sh";
    // handlers[0].priority_order = 1;
    // num_handlers = 1;
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

// Parse scan script output
static void parse_scan_output(const char* line, cve_scan_result_t* result) {
    if (strstr(line, "VULNERABLE:")) {
        sscanf(line, "VULNERABLE:%d", &result->is_vulnerable);
    } else if (strstr(line, "CONFIDENCE:")) {
        sscanf(line, "CONFIDENCE:%d", &result->confidence);
    } else if (strstr(line, "PORT_OPEN:")) {
        sscanf(line, "PORT_OPEN:%d", &result->port_open);
    } else if (strstr(line, "SERVICE:")) {
        sscanf(line, "SERVICE:%31s", result->service_type);
    }
}

// Call scan handler (Phase 1)
cve_scan_result_t call_scan_handler(cve_handler_config_t* handler, const char* target_ip) {
    cve_scan_result_t result = {0};
    
    if (!handler || !handler->scan_script_path) {
        return result;
    }
    
    // Build command
    char command[512];
    snprintf(command, sizeof(command), "%s %s", handler->scan_script_path, target_ip);
    
    // Execute scan script
    FILE* fp = popen(command, "r");
    if (!fp) {
        return result;
    }
    
    // Parse script output
    char buffer[256];
    result.cve_id = handler->cve_id;
    
    while (fgets(buffer, sizeof(buffer), fp)) {
        // Remove newline
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len - 1] == '\n') {
            buffer[len - 1] = '\0';
        }
        
        parse_scan_output(buffer, &result);
    }
    
    pclose(fp);
    return result;
}

// Call execution handler (Phase 3)
int call_execution_handler(cve_handler_config_t* handler, const char* target_ip) {
    if (!handler || !handler->execution_script_path) {
        return 0;
    }
    
    // Build command
    char command[512];
    snprintf(command, sizeof(command), "%s %s", handler->execution_script_path, target_ip);
    
    // Execute execution script
    int result = system(command);
    return (result == 0) ? 1 : 0;  // 1 = success, 0 = failure
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

