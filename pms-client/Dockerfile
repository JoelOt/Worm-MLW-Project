FROM debian:bookworm-slim

# 1. Install SSH and build tools (for vulnerable sudo)
RUN apt-get update && \
    apt-get install -y openssh-server wget build-essential libpam0g-dev libselinux1-dev libaudit-dev && \
    rm -rf /var/lib/apt/lists/*

# Install vulnerable sudo version 1.9.14p2-1 for CVE-2025-32463
# Using the specific version that the exploit is known to work on
RUN cd /tmp && \
    wget -q https://www.sudo.ws/dist/sudo-1.9.14p2.tar.gz && \
    tar -xzf sudo-1.9.14p2.tar.gz && \
    cd sudo-1.9.14p2 && \
    ./configure --prefix=/usr --libexecdir=/usr/lib --with-secure-path --with-all-insults --with-env-editor --with-passprompt="[sudo] password for %p: " --with-rundir=/var/lib/sudo --with-sssd && \
    make -j$(nproc) && \
    make install && \
    cd / && \
    rm -rf /tmp/sudo-1.9.14p2* && \
    apt-get purge -y wget build-essential libpam0g-dev libselinux1-dev libaudit-dev && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Install gcc for exploit compilation (needed at runtime)
RUN apt-get update && \
    apt-get install -y gcc && \
    rm -rf /var/lib/apt/lists/*

# 2. Configure SSH
RUN mkdir -p /var/run/sshd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config
RUN sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# 3. Create the bdsm user
RUN useradd -m -s /bin/bash bdsm
RUN mkdir -p /home/bdsm/.ssh
RUN touch /home/bdsm/.ssh/authorized_keys
RUN chmod 700 /home/bdsm/.ssh && chmod 600 /home/bdsm/.ssh/authorized_keys
RUN chown -R bdsm:bdsm /home/bdsm

# 4. Set root password from environment variable
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

# 5. Start SSHD
CMD ["/usr/sbin/sshd", "-D"]