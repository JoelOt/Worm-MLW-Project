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

# Create ubuntu user
RUN useradd -m -s /bin/bash ubuntu

# Create SSH directory for ubuntu user
RUN mkdir -p /home/ubuntu/.ssh && \
    chmod 700 /home/ubuntu/.ssh && \
    chown ubuntu:ubuntu /home/ubuntu/.ssh

# Copy the shared SSH key pair
COPY shared_key /home/ubuntu/.ssh/id_rsa
COPY shared_key.pub /home/ubuntu/.ssh/id_rsa.pub

# Set up authorized_keys for ubuntu user
RUN cat /home/ubuntu/.ssh/id_rsa.pub > /home/ubuntu/.ssh/authorized_keys && \
    chmod 600 /home/ubuntu/.ssh/authorized_keys && \
    chmod 600 /home/ubuntu/.ssh/id_rsa && \
    chown ubuntu:ubuntu /home/ubuntu/.ssh/*

# Configure SSH to allow ubuntu login and key-based authentication, disable root
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
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
