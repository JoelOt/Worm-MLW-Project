#ifndef CVE_SHADOW_EXFILTRATION_H
#define CVE_SHADOW_EXFILTRATION_H

#include "handler_registry.h"

// CVE ID for Shadow File Exfiltration (defined in handler_registry.h as CVE_SHADOW_EXFILTRATION)

cve_scan_result_t cve_shadow_exfiltration_scan(const char* target_ip);
int cve_shadow_exfiltration_execute(const char* target_ip);

#endif // CVE_SHADOW_EXFILTRATION_H

