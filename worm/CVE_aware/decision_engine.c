#include "decision_engine.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Decision rules (hardcoded for now)
static cve_decision_rule_t decision_rules[MAX_CVE_HANDLERS];
static int num_rules = 0;

// Initialize decision rules
void init_decision_rules(void) {
    num_rules = 0;
    
    // Decision rule for CVE-2014-6271 (Shellshock)
    decision_rules[0].cve_id = CVE_2014_6271;
    decision_rules[0].priority_order = 1;
    decision_rules[0].requires_vulnerable = 1;      // Must be vulnerable
    decision_rules[0].requires_port_open = 80;      // Port 80 must be open
    decision_rules[0].min_confidence = 7;           // Minimum confidence 7/10
    decision_rules[0].max_risk_level = 5;           // Don't use if risk > 5
    decision_rules[0].stealth_required = 0;         // Can use in normal mode
    num_rules = 1;
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
decision_result_t make_decision(cve_result_vector_t* scan_results, 
                                risk_assessment_t* risk, 
                                degradation_mode_t mode) {
    decision_result_t result = {0};
    
    // Sort rules by priority (simple: iterate in order)
    // For now, assume rules are already in priority order
    
    for (int i = 0; i < num_rules; i++) {
        cve_decision_rule_t* rule = &decision_rules[i];
        
        // Check all conditions
        if (!check_vulnerable(rule, scan_results)) continue;
        if (!check_port(rule, scan_results)) continue;
        if (!check_confidence(rule, scan_results)) continue;
        if (!check_risk(rule, risk)) continue;
        if (!check_mode(rule, mode)) continue;
        
        // All conditions satisfied - select this CVE
        result.selected_cve_id = rule->cve_id;
        result.should_execute = 1;
        return result;  // Stop at first match
    }
    
    // No CVE selected
    result.should_execute = 0;
    return result;
}

