# CVE-Aware, Safely-Degrading Malware: Architecture & Overview

## Project Overview

**Goal**: Build a CVE-Aware, Safely-Degrading Malware worm that adapts to its environment and degrades gracefully when detection risk is high.

**Key Features**:
- Risk-aware operation (assesses detection risk before acting)
- Multi-CVE support (can exploit multiple vulnerabilities)
- Adaptive behavior (self-destruct or stealth mode based on risk)
- Scalable architecture (easy to add new CVEs)

---

## System Architecture: 4-Phase Engine

```
┌─────────────────────────────────────────────────────────────┐
│                    PHASE 0: RISK ASSESSMENT                  │
│  Monitor → Calculate Risk Score (0-10) → Determine Action   │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
        ┌───────────────────────────────────────┐
        │  Risk Score Decision Point            │
        └───────────────────────────────────────┘
                    │
        ┌───────────┼───────────┐
        │           │           │
        ▼           ▼           ▼
    HIGH (7-10)  MODERATE   LOW (0-3)
    │           (4-6)       │
    │           │           │
    ▼           ▼           ▼
SELF-DESTRUCT  STEALTH    PROCEED
    │           │           │
    │           │           ▼
    │           │    ┌──────────────────────┐
    │           │    │  PHASE 1: SCAN        │
    │           │    │  CVE Scan Handlers    │
    │           │    │  → Result Vector      │
    │           │    └──────────────────────┘
    │           │              │
    │           │              ▼
    │           │    ┌──────────────────────┐
    │           │    │  PHASE 2: DECISION   │
    │           │    │  Priority-Ordered    │
    │           │    │  → Decision Vector   │
    │           │    └──────────────────────┘
    │           │              │
    │           │              ▼
    │           │    ┌──────────────────────┐
    │           │    │  PHASE 3: EXECUTE    │
    │           │    │  CVE Exploit Handlers│
    │           │    │  → Success/Failure    │
    │           │    └──────────────────────┘
    │           │              │
    │           └──────────────┘
    │                  │
    └──────────────────┘
            │
            ▼
    Continue Loop or Exit
```

---

## Phase 0: Risk Assessment

**Purpose**: Assess detection risk before any operations

**Input**: Environment signals (network, system, behavioral)
**Output**: Risk score (0-10) and action decision

**Risk Calculation**:
- **Network Risk (40%)**: Failed connections, IDS alerts, traffic anomalies
- **System Risk (30%)**: CPU/memory usage, process anomalies
- **Behavioral Risk (30%)**: Failed operations, rapid activity, resource exhaustion

**Total Risk = (Network × 0.4) + (System × 0.3) + (Behavioral × 0.3)**

**Decisions**:
- **HIGH (7-10)**: Self-destruct immediately → Exit
- **MODERATE (4-6)**: Enter stealth mode → Skip scan, reduce activity
- **LOW (0-3)**: Proceed to Scan Phase

---

## Phase 1: Scan

**Purpose**: Gather intelligence about targets

**Process**:
- Call registered CVE scan handlers (scripts)
- Collect results in standard format
- Build result vector (which CVEs are vulnerable)

**Engine Responsibility**: Call handlers, collect results
**Handler Responsibility**: Implement scanning (local/remote/passive - handler's choice)

---

## Phase 2: Decision

**Purpose**: Choose which CVE to execute

**Process**: Priority-ordered list, first match wins

**Algorithm**:
1. Iterate through CVEs in priority order
2. Check conditions for each CVE:
   - Vulnerable? (from scan)
   - Port open? (from scan)
   - Confidence sufficient? (from scan)
   - Risk acceptable? (from risk assessment)
   - Mode compatible? (normal vs stealth)
3. **First CVE that satisfies all conditions is selected**
4. Stop evaluation (don't check lower priority)

---

## Phase 3: Execute

**Purpose**: Execute selected CVE exploit

**Process**: Call exploit handler (script)

**Output**: Success/failure

---

## State Machine: Linear Flow

**Simplest Approach**: No explicit state machine, just a loop:

```c
int main() {
    while (1) {
        // Phase 0: Risk Assessment
        risk = assess_risk();
        if (risk >= 7) { self_destruct(); break; }
        if (risk >= 4) { stealth_mode(); continue; }
        
        // Phase 1: Scan
        scan();
        
        // Phase 2: Decision
        decide();
        
        // Phase 3: Execute
        execute();
        
        sleep(20);
    }
}
```

---

## Degradation Modes

### Self-Destruction Mode
- **Trigger**: Risk >= 7
- **Behavior**: Clean exit, remove traces, delete files
- **Use Case**: High detection risk

### Stealth Mode
- **Trigger**: Risk 4-6
- **Behavior**: Reduce activity, use quieter CVEs, longer delays
- **Use Case**: Moderate risk, want persistence

---

## Key Design Principles

1. **Engine-Handler Separation**: Engine = "What to do", Handlers = "How to do it"
2. **Risk-Aware**: Always assess risk before operations
3. **Priority-Based**: First match wins in decision phase
4. **Scalable**: Easy to add new CVEs (just add scripts)
5. **Simple**: Minimal state, linear flow, script-based handlers

---

## Folder Structure

```
worm/
  ├── worm (main binary)
  ├── exploits/
  │   ├── cve-2014-6271.sh
  │   ├── cve-2014-0160.sh
  │   └── ...
  └── scans/
      ├── cve-2014-6271-scan.sh
      └── ...
```

