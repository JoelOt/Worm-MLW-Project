#!/bin/bash

CONTAINERS=("ubuntu2" "ubuntu3" "ubuntu4" "ubuntu5")
WORM_PATH="/tmp/worm"

declare -A HASHES

echo "=== Verifying Worm Propagation & Polymorphism ==="

for container in "${CONTAINERS[@]}"; do
    echo "---------------------------------------------------"
    echo "Checking container: $container"

    # Check if worm file exists
    if sudo docker exec "$container" test -f "$WORM_PATH"; then
        echo "[+] $WORM_PATH FOUND"

        # Calculate hash
        HASH=$(sudo docker exec "$container" sha256sum "$WORM_PATH" | awk '{print $1}')
        HASHES["$container"]="$HASH"
        echo "[+] SHA256: $HASH"
    else
        echo "[-] $WORM_PATH NOT FOUND"
        continue
    fi
    # Check if process is running (C binary)
    if sudo docker exec "$container" pgrep -f "$WORM_PATH" > /dev/null 2>&1; then
        echo "[+] Worm process IS RUNNING"
    else
        echo "[-] Worm process is NOT RUNNING"
    fi

done

echo "---------------------------------------------------"
echo "=== Polymorphism Verification ==="

UNIQUE_HASHES=$(printf "%s\n" "${HASHES[@]}" | sort -u | wc -l)
TOTAL_HASHES=${#HASHES[@]}

if [ "$UNIQUE_HASHES" -eq "$TOTAL_HASHES" ]; then
    echo "[+] SUCCESS: All instances are different (polymorphism confirmed)"
else
    echo "[-] WARNING: Some instances share the same hash"
fi

echo "---------------------------------------------------"
