# SSH Key-Based Worm Environment
FROM ubuntu:20.04

LABEL maintainer="SSH Worm Testing Environment"

# Prevent interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Install OpenSSH server and necessary tools
RUN apt-get update && \
    apt-get install -y openssh-server build-essential net-tools && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create SSH directory
RUN mkdir -p /root/.ssh && \
    chmod 700 /root/.ssh

# Generate a shared SSH key pair that all containers will use
# This allows worm propagation between containers
RUN ssh-keygen -t rsa -b 2048 -f /root/.ssh/id_rsa -N "" && \
    cat /root/.ssh/id_rsa.pub > /root/.ssh/authorized_keys && \
    chmod 600 /root/.ssh/authorized_keys && \
    chmod 600 /root/.ssh/id_rsa

# Configure SSH to allow root login and key-based authentication
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config && \
    echo "StrictHostKeyChecking no" >> /etc/ssh/ssh_config && \
    echo "UserKnownHostsFile=/dev/null" >> /etc/ssh/ssh_config

# Create the privilege separation directory required by sshd
RUN mkdir -p /run/sshd

# Expose SSH port
EXPOSE 22

# Start SSH server
CMD ["/usr/sbin/sshd", "-D"]
