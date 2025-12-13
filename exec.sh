#!/bin/bash

sudo docker compose -f docker-compose.yml down
sudo docker compose -f docker-compose.yml build
sudo docker compose -f docker-compose.yml up -d 

# Copy source file to container
sudo docker cp ./worm/worm.c ubuntu1:/tmp/worm.c

# Install gcc if not present and compile inside container
echo "installing gcc"
sudo docker exec ubuntu1 bash -c "apt-get update -qq && apt-get install -y -qq gcc > /dev/null 2>&1 || true"

echo "compiling worm"
sudo docker exec ubuntu1 gcc -Wall -Wextra -std=c11 -o /tmp/worm /tmp/worm.c

# Make executable
echo "making executable"
sudo docker exec ubuntu1 chmod +x /tmp/worm

# Run the worm
echo "running worm"
sudo docker exec -d ubuntu1 /tmp/worm
