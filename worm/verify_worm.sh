#!/bin/bash

CONTAINERS=("ubuntu2" "ubuntu3" "ubuntu4" "ubuntu5")

echo "=== Verifying Worm Propagation ==="

for container in "${CONTAINERS[@]}"; do
    echo "---------------------------------------------------"
    echo "Checking container: $container"
    
    # Check if worm file exists
    if sudo docker exec $container ls /tmp/worm.py > /dev/null 2>&1; then
        echo "[+] /tmp/worm.py FOUND"
    else
        echo "[-] /tmp/worm.py NOT FOUND"
    fi

    # Check if process is running
    if sudo docker exec $container ps aux | grep "python3 /tmp/worm.py" | grep -v grep > /dev/null 2>&1; then
        echo "[+] Worm process IS RUNNING"
    else
        echo "[-] Worm process is NOT RUNNING"
    fi
done
echo "---------------------------------------------------"
