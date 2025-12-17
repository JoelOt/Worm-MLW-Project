#ifndef DECISION_ENGINE_H
#define DECISION_ENGINE_H

#include "handler_registry.h"
#include "risk_assessment.h"

typedef enum {
    MODE_NORMAL,
    MODE_STEALTH,
    MODE_SELF_DESTRUCT
} degradation_mode_t;

typedef struct {
    int cve_id;
    int priority_order;        // Order in list (1 = highest)
    int requires_vulnerable;   // Must be vulnerable
    int requires_port_open;    // Port requirement
    int min_confidence;        // Minimum confidence (0-10)
    int max_risk_level;        // Maximum risk to attempt (0-10)
    int stealth_required;      // Only in stealth mode (0 or 1)
} cve_decision_rule_t;

typedef struct {
    int selected_cve_id;
    int should_execute;
} decision_result_t;

// Initialize decision rules
void init_decision_rules(void);

// Main decision function (Phase 2)
decision_result_t make_decision(cve_result_vector_t* scan_results, 
                                risk_assessment_t* risk, 
                                degradation_mode_t mode);

#endif // DECISION_ENGINE_H

