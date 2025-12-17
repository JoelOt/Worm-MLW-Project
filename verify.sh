#!/usr/bin/env bash

CONTAINERS=("local_site_1" "local_site_2" "local_site_3")

WORM_PATH="/tmp/worm"

HASHES_FILE=$(mktemp)
trap "rm -f $HASHES_FILE" EXIT

echo "=== Verifying Worm Propagation & Polymorphism ==="

TOTAL_FOUND=0

for container in "${CONTAINERS[@]}"; do
    echo "---------------------------------------------------"
    echo "Checking container: $container"

    # Check if worm file exists
    if docker exec "$container" test -f "$WORM_PATH" 2>/dev/null; then
        echo "[+] $WORM_PATH FOUND"

        # Calculate hash
        HASH=$(docker exec "$container" sha256sum "$WORM_PATH" 2>/dev/null | awk '{print $1}')
        if [ -n "$HASH" ]; then
            echo "$HASH" >> "$HASHES_FILE"
            echo "[+] SHA256: $HASH"
            TOTAL_FOUND=$((TOTAL_FOUND + 1))
        fi
    else
        echo "[-] $WORM_PATH NOT FOUND"
        continue
    fi
    # Check if process is running (C binary)
    if docker exec "$container" pgrep -f "$WORM_PATH" > /dev/null 2>&1; then
        echo "[+] Worm process IS RUNNING"
    else
        echo "[-] Worm process is NOT RUNNING"
    fi

done

echo "---------------------------------------------------"
echo "=== Polymorphism Verification ==="

if [ "$TOTAL_FOUND" -eq 0 ]; then
    echo "[-] ERROR: No worm files found in any container"
    echo "---------------------------------------------------"
    exit 1
fi

UNIQUE_HASHES=$(sort -u "$HASHES_FILE" | wc -l | tr -d ' ')

if [ "$UNIQUE_HASHES" -eq "$TOTAL_FOUND" ] && [ "$TOTAL_FOUND" -gt 1 ]; then
    echo "[+] SUCCESS: All $TOTAL_FOUND instances are different (polymorphism confirmed)"
elif [ "$UNIQUE_HASHES" -lt "$TOTAL_FOUND" ]; then
    echo "[-] WARNING: Some instances share the same hash ($UNIQUE_HASHES unique out of $TOTAL_FOUND total)"
else
    echo "[*] Only 1 instance found - cannot verify polymorphism"
fi

echo "---------------------------------------------------"
echo "=== Shadow File Exfiltration Verification ==="

C2_SHADOW_DIR="/c2/credentials/new"
SHADOW_COUNT=0

# Check if C2 container exists and shadow directory is accessible
if docker exec c2 test -d "$C2_SHADOW_DIR" 2>/dev/null; then
    # Count shadow files
    SHADOW_COUNT=$(docker exec c2 find "$C2_SHADOW_DIR" -name "shadow_*" -type f 2>/dev/null | wc -l | tr -d ' ')
    
    if [ "$SHADOW_COUNT" -gt 0 ]; then
        echo "[+] Found $SHADOW_COUNT exfiltrated shadow file(s) in C2 server"
        
        # List recent shadow files (last 5)
        echo "[*] Recent shadow files:"
        docker exec c2 ls -lt "$C2_SHADOW_DIR" 2>/dev/null | grep "shadow_" | head -5 | awk '{print "    " $9 " (" $5 " " $6 " " $7 " " $8 ")"}'
        
        # Check if files have content (check total size of all shadow files)
        TOTAL_SIZE=$(docker exec c2 sh -c "find $C2_SHADOW_DIR -name 'shadow_*' -type f -exec stat -c%s {} \; 2>/dev/null | awk '{s+=\$1} END {print s}'" 2>/dev/null || echo "0")
        
        if [ "$TOTAL_SIZE" -gt 0 ]; then
            echo "[+] All shadow files contain data (total size: $TOTAL_SIZE bytes)"
        else
            echo "[-] WARNING: Shadow files appear to be empty"
        fi
    else
        echo "[-] No shadow files found in C2 server"
        echo "[*] Expected shadow files in: $C2_SHADOW_DIR"
    fi
else
    echo "[-] C2 container or shadow directory not accessible"
    echo "[*] Expected directory: $C2_SHADOW_DIR"
fi

echo "---------------------------------------------------"
