#!/bin/bash
set -e

# 1. Handle SSH Key Injection
# If the temporary mount file exists...
if [ -f "/tmp/ssh_key.pub" ]; then
    echo "Loading SSH key from mount..."
    # Copy the content (this creates a new file owned by root initially)
    cat /tmp/ssh_key.pub > /home/bdsm/.ssh/authorized_keys
    
    # NOW we can force the ownership and permissions on the internal file
    chown bdsm:bdsm /home/bdsm/.ssh/authorized_keys
    chmod 600 /home/bdsm/.ssh/authorized_keys
fi

# 2. Build-time password logic
if [ -n "$ROOT_PASSWORD" ]; then
    echo "root:$ROOT_PASSWORD" | chpasswd
fi

# Execute the CMD passed in the Dockerfile (starts sshd)
exec "$@"