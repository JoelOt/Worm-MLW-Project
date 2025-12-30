#ifndef RISK_ASSESSMENT_H
#define RISK_ASSESSMENT_H

typedef struct {
    int network_risk;      // 0-10 (40% weight)
    int system_risk;       // 0-10 (30% weight)
    int behavioral_risk;   // 0-10 (30% weight)
    int total_risk;        // 0-10 (weighted sum)
} risk_assessment_t;

// Main risk assessment function (Phase 0)
risk_assessment_t assess_risk(void);

// Update behavioral signals (call after operations)
void update_failed_connection(void);
void update_failed_operation(void);
void update_successful_operation(void);

#endif // RISK_ASSESSMENT_H

