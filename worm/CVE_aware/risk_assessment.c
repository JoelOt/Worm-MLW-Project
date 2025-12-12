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
    // Simplified: count failed connections
    // In a real implementation, this would check:
    // - IDS alerts
    // - Traffic anomalies
    // - Rate limiting
    return failed_connections;
}

// System signal collection
static int collect_system_signals(void) {
    // Simplified: check CPU/memory usage
    // In a real implementation, this would read /proc/stat, /proc/meminfo
    // For now, return 0 (low system risk)
    return 0;
}

// Behavioral signal collection
static int collect_behavioral_signals(void) {
    // Calculate based on success/failure ratio
    int total_ops = failed_operations + successful_operations;
    if (total_ops == 0) return 0;
    
    // High failure rate = high risk
    double failure_rate = (double)failed_operations / total_ops;
    return (int)(failure_rate * 10);
}

// Calculate network risk (0-10)
static int calculate_network_risk(int failed_conns) {
    // Simple mapping: 0-2 failed = low risk, 3-5 = moderate, 6+ = high
    if (failed_conns == 0) return 0;
    if (failed_conns <= 2) return 2;
    if (failed_conns <= 5) return 5;
    if (failed_conns <= 10) return 8;
    return 10;
}

// Calculate system risk (0-10)
static int calculate_system_risk(int sys_signal) {
    // Simplified: return system signal as-is
    return sys_signal;
}

// Calculate behavioral risk (0-10)
static int calculate_behavioral_risk(int beh_signal) {
    // Return behavioral signal as-is (already 0-10)
    return beh_signal;
}

// Main risk assessment function
risk_assessment_t assess_risk(void) {
    risk_assessment_t risk = {0};
    
    // Collect signals
    int net_signal = collect_network_signals();
    int sys_signal = collect_system_signals();
    int beh_signal = collect_behavioral_signals();
    
    // Calculate individual risks
    risk.network_risk = calculate_network_risk(net_signal);
    risk.system_risk = calculate_system_risk(sys_signal);
    risk.behavioral_risk = calculate_behavioral_risk(beh_signal);
    
    // Weighted total: Network 40%, System 30%, Behavioral 30%
    risk.total_risk = (int)(
        (risk.network_risk * 0.40) +
        (risk.system_risk * 0.30) +
        (risk.behavioral_risk * 0.30)
    );
    
    // Clamp to 0-10
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

