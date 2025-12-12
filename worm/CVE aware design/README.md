# CVE-Aware Design Documentation

## Overview

This folder contains the complete design documentation for the **CVE-Aware, Safely-Degrading Malware** project, consolidated into 3 comprehensive documents.

## Design Documents

### 1. **01_ARCHITECTURE_AND_OVERVIEW.md** ⭐ START HERE
- Project overview and goals
- 4-phase engine architecture
- Risk assessment overview
- Degradation modes overview
- Key design principles
- Folder structure

### 2. **02_PHASES_AND_FLOW.md**
- Detailed phase implementations
- Risk assessment (signals, calculation, thresholds)
- Scan phase (engine interface, handler options)
- Decision phase (rules, algorithm, examples)
- Execute phase (engine interface, script interface)
- Degradation modes (self-destruct, stealth)
- State management (in-memory tracking)
- Complete flow examples

### 3. **03_HANDLERS_AND_IMPLEMENTATION.md**
- Handler architecture (script-based)
- Handler registration system
- Script interfaces (scan and exploit)
- Engine calls handlers
- Author responsibility (making scripts undetectable)
- Example handler scripts
- State management implementation
- Handler scanning methods
- Adding new CVEs
- Best practices

---

## Quick Reference

**Architecture**: 4-Phase Engine (Risk Assessment → Scan → Decision → Execute)

**Handlers**: Script-based (exploits in `exploits/` folder)

**Decision**: Priority-ordered list (first match wins)

**State**: In-memory (track infected IPs)

**Flow**: Linear loop (no explicit state machine)

**Degradation**: Self-destruct (risk >= 7) or Stealth (risk 4-6)

---

## Key Design Principles

1. **Engine-Handler Separation**: Engine = "What to do", Handlers = "How to do it"
2. **Risk-Aware**: Always assess risk before operations
3. **Priority-Based**: First match wins in decision phase
4. **Scalable**: Easy to add new CVEs (just add scripts)
5. **Simple**: Minimal state, linear flow, script-based handlers

---

## Implementation Checklist

- [ ] Phase 0: Risk Assessment module
- [ ] Phase 1: Scan phase (call scan scripts)
- [ ] Phase 2: Decision phase (priority-ordered selection)
- [ ] Phase 3: Execute phase (call exploit scripts)
- [ ] State management (track infected IPs)
- [ ] Degradation modes (self-destruct, stealth)
- [ ] Handler registration system
- [ ] Script interface (input/output format)

