#ifndef CVE_2014_6271_H
#define CVE_2014_6271_H

#include "handler_registry.h"

// CVE-2014-6271 (Shellshock) handlers
cve_scan_result_t cve_2014_6271_scan(const char* target_ip);
int cve_2014_6271_execute(const char* target_ip);

#endif // CVE_2014_6271_H

