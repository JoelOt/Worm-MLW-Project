#ifndef STATE_MANAGER_H
#define STATE_MANAGER_H

// Initialize state management
void init_state(void);

// Check if IP is already infected
int is_infected(const char* ip);

// Mark IP as infected
void mark_infected(const char* ip);

// Clear state (for cleanup)
void clear_state(void);

#endif // STATE_MANAGER_H

