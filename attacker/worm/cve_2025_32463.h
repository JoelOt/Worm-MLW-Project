#ifndef CVE_2025_32463_H
#define CVE_2025_32463_H

/**
 * CVE-2025-32463: Sudo NSS Injection Privilege Escalation
 * 
 * Vulnerability: sudo versions 1.9.14 < 1.9.17p1
 * Allows local privilege escalation via NSS module injection in chroot
 */

/**
 * Scan for CVE-2025-32463 vulnerability
 * Checks if sudo version is vulnerable (1.9.14 < 1.9.17p1)
 * Returns 1 if vulnerable, 0 if not
 */
int cve_2025_32463_scan(void);

/**
 * Execute CVE-2025-32463 privilege escalation exploit
 * Returns 1 on success (root shell obtained), 0 on failure
 */
int cve_2025_32463_execute(void);

#endif // CVE_2025_32463_H
