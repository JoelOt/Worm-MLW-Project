#!/bin/bash

# Copy source file to container
sudo docker cp worm.c ubuntu1:/tmp/worm.c

# Install gcc if not present and compile inside container
sudo docker exec ubuntu1 bash -c "apt-get update -qq && apt-get install -y -qq gcc > /dev/null 2>&1 || true"
sudo docker exec ubuntu1 gcc -Wall -Wextra -std=c11 -o /tmp/worm /tmp/worm.c

# Make executable
sudo docker exec ubuntu1 chmod +x /tmp/worm

# Run the worm
sudo docker exec -d ubuntu1 /tmp/worm
