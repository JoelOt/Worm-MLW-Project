#!/usr/bin/env python3
import subprocess
import time
import random
import sys
import os

# Configuration
SUBNETS = [
    "172.28.1",  # net_1_2 (ubuntu1-ubuntu2)
    "172.28.2",  # net_1_3 (ubuntu1-ubuntu3)
    "172.28.3",  # net_2_4 (ubuntu2-ubuntu4)
    "172.28.4",  # net_3_5 (ubuntu3-ubuntu5)
]

def scan_target(ip):
    """
    Scans the target IP for port 80 using nmap.
    Returns True if port 80 is open, False otherwise.
    """
    print(f"[*] Scanning {ip} for port 80...")
    try:
        # Run nmap to check port 80
        # -p 80: scan port 80
        # --open: only show open ports
        # -n: no DNS resolution
        # -Pn: treat as online (skip host discovery)
        result = subprocess.run(
            ["nmap", "-p", "80", "--open", "-n", "-Pn", ip],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if "80/tcp open" in result.stdout:
            return True
        return False
    except FileNotFoundError:
        print("[-] Error: nmap not found. Please install nmap.")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error scanning {ip}: {e}")
        return False

def infect_target(ip):
    """
    Simulates infection of the target.
    Since we are not using SSH, we cannot copy the file without an exploit.
    This function represents the payload delivery phase.
    """
    if scan_target(ip):
        print(f"[+] Web Server found at {ip}!")
        print(f"[*] Attempting infection on {ip}...")
        
        # In a real worm, this would be where we exploit a vulnerability 
        # (e.g., SQLi, RCE, file upload) to transfer and execute the worm.
        # Since we are only scanning, we simulate the success.
        
        print(f"[+] INFECTED: {ip} (Simulated)")
        return True
    else:
        # print(f"[-] Port 80 closed on {ip}")
        return False


def main():
    print("=== Python Worm - Nmap Scanner Variant ===")
    
    # Seed random (not strictly needed for this variant but good practice)
    random.seed()

    while True:
        print("\n[*] Starting infection round...")
        
        for subnet in SUBNETS:
            # Try hosts .2 and .3 in each subnet (matching original worm.c logic)
            for host in range(2, 4):
                ip = f"{subnet}.{host}"
                infect_target(ip)
        
        print("[*] Round complete. Sleeping 10 seconds...")
        time.sleep(10)

if __name__ == "__main__":
    main()
