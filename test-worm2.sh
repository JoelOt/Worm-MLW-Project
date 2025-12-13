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
sudo docker cp worm/worm.c ubuntu1-ssh:/tmp/worm.c

echo ""
echo "[5/5] Compiling worm inside container..."
sudo docker exec ubuntu1-ssh gcc -o /tmp/worm /tmp/worm.c -Wall
sudo docker exec ubuntu1-ssh chmod +x /tmp/worm
