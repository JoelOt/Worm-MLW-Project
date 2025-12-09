#!/bin/bash

check_host() {
    local host=$1
    local ip=$2
    local name=$3
    
    echo "═══ $name ($ip) ═══"
    
    # Check for worm binary and size
    echo "Worm binary:"
    sudo docker exec $host ls -l --block-size=1 /tmp/worm 2>/dev/null || echo "  ❌ Not found"
    echo ""
    
    # Check if worm is running
    echo "Worm process:"
    sudo docker exec $host ps aux | grep -E '/tmp/worm( |$)' | grep -v grep || echo "  ❌ Not running"
    echo ""

    # Check worm signature (Polymorphism verify)
    echo "Worm MD5 Signature:"
    sudo docker exec $host md5sum /tmp/worm 2>/dev/null || echo "  ❌ Cannot calculate hash"
    echo ""
    
    echo "───────────────────────────────────────────────────────────"
    echo ""
}

check_host "ubuntu2" "172.28.1.3" "UBUNTU2"
check_host "ubuntu3" "172.28.2.3" "UBUNTU3"
check_host "ubuntu4" "172.28.3.3" "UBUNTU4"
check_host "ubuntu5" "172.28.4.3" "UBUNTU5"

echo "═══ SUMMARY ═══"
infected=0
for host in ubuntu2 ubuntu3 ubuntu4 ubuntu5; do
    if sudo docker exec $host test -f /tmp/worm 2>/dev/null; then
        infected=$((infected + 1))
    fi
done

echo "✓ Infected hosts: $infected/4"
