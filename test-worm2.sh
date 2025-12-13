#!/bin/bash
# Test script for SSH-based worm (worm2)

set -e

echo "=== SSH Worm Testing Script ==="
echo ""

# Build the Docker environment
sudo docker compose -f docker-compose-ssh.yml down
sudo docker compose -f docker-compose-ssh.yml build

sudo docker compose -f docker-compose-ssh.yml up -d

echo ""
sleep 5

echo ""
sudo docker cp worm/worm2.c ubuntu1-ssh:/tmp/worm2.c

echo ""
echo "[5/5] Compiling worm2 inside container..."
sudo docker exec ubuntu1-ssh gcc -o /tmp/worm2 /tmp/worm2.c -Wall
sudo docker exec ubuntu1-ssh chmod +x /tmp/worm2
