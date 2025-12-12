#ifndef DEGRADATION_H
#define DEGRADATION_H

// Self-destruct: Clean exit, remove traces
void self_destruct(void);

// Enter stealth mode: Reduce activity, longer delays
void enter_stealth_mode(void);

// Perform stealth operations (minimal activity)
void perform_stealth_operations(void);

// Cleanup functions
void cleanup_files(void);
void cleanup_processes(void);

#endif // DEGRADATION_H

