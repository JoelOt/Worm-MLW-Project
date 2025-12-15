#!/bin/bash

CONTAINERS=("local_site_1" "local_site_2" "local_site_3")

WORM_PATH="/tmp/worm"

# Use associative array if available (bash 4+), otherwise use regular array
if declare -A HASHES_TEST &>/dev/null; then
declare -A HASHES
    USE_ASSOC_ARRAY=1
else
    USE_ASSOC_ARRAY=0
    HASHES=()
    HASH_KEYS=()
fi

echo "=== Verifying Worm Propagation & Polymorphism ==="

for container in "${CONTAINERS[@]}"; do
    echo "---------------------------------------------------"
    echo "Checking container: $container"

    # Check if worm file exists (without sudo)
    if docker exec "$container" test -f "$WORM_PATH" 2>/dev/null; then
        echo "[+] $WORM_PATH FOUND"

        # Calculate hash
        HASH=$(docker exec "$container" sha256sum "$WORM_PATH" 2>/dev/null | awk '{print $1}')
        if [ -n "$HASH" ]; then
            if [ $USE_ASSOC_ARRAY -eq 1 ]; then
        HASHES["$container"]="$HASH"
            else
                HASHES+=("$HASH")
                HASH_KEYS+=("$container")
            fi
        echo "[+] SHA256: $HASH"
        fi
    else
        echo "[-] $WORM_PATH NOT FOUND"
        continue
    fi
    
    # Check if process is running (C binary)
    if docker exec "$container" pgrep -f "$WORM_PATH" > /dev/null 2>&1; then
        echo "[+] Worm process IS RUNNING"
        
        # Check if privilege escalation happened (CVE-2025-32463)
        # Get the PID of the worm process
        WORM_PID=$(docker exec "$container" pgrep -f "$WORM_PATH" 2>/dev/null | head -1)
        if [ -n "$WORM_PID" ]; then
            # Check if running as root (uid 0)
            WORM_UID=$(docker exec "$container" ps -o uid= -p "$WORM_PID" 2>/dev/null | tr -d ' ')
            if [ "$WORM_UID" = "0" ]; then
                echo "[+] Privilege escalation SUCCESSFUL (running as root, uid=0)"
            else
                echo "[-] Privilege escalation NOT detected (running as uid=$WORM_UID)"
            fi
        fi
        
        # Also check sudo version to confirm vulnerability exists
        SUDO_VERSION=$(docker exec "$container" sudo --version 2>&1 | head -1)
        if echo "$SUDO_VERSION" | grep -qE "1\.9\.(1[4-6]|17)"; then
            echo "[+] Vulnerable sudo version detected: $SUDO_VERSION"
        else
            echo "[-] Sudo version check: $SUDO_VERSION"
        fi
    else
        echo "[-] Worm process is NOT RUNNING"
    fi

done

echo "---------------------------------------------------"
echo "=== Polymorphism Verification ==="

if [ $USE_ASSOC_ARRAY -eq 1 ]; then
    UNIQUE_HASHES=$(printf "%s\n" "${HASHES[@]}" | sort -u | wc -l)
    TOTAL_HASHES=${#HASHES[@]}
else
UNIQUE_HASHES=$(printf "%s\n" "${HASHES[@]}" | sort -u | wc -l)
TOTAL_HASHES=${#HASHES[@]}
fi

if [ "$UNIQUE_HASHES" -eq "$TOTAL_HASHES" ] && [ "$TOTAL_HASHES" -gt 0 ]; then
    echo "[+] SUCCESS: All instances are different (polymorphism confirmed)"
else
    if [ "$TOTAL_HASHES" -eq 0 ]; then
        echo "[-] WARNING: No worm instances found to verify"
else
    echo "[-] WARNING: Some instances share the same hash"
    fi
fi

echo "---------------------------------------------------"
