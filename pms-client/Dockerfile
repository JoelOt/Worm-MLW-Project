FROM debian:bookworm-slim

# 1. Install SSH
RUN apt-get update && \
    apt-get install -y openssh-server && \
    rm -rf /var/lib/apt/lists/*

# 2. Configure SSH
RUN mkdir -p /var/run/sshd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
RUN sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
#RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# 3. Create the bdsm user
#RUN useradd -m -s /bin/bash bdsm
#RUN mkdir -p /home/bdsm/.ssh
#RUN touch /home/bdsm/.ssh/authorized_keys
#RUN chmod 700 /home/bdsm/.ssh && chmod 600 /home/bdsm/.ssh/authorized_keys
#RUN chown -R bdsm:bdsm /home/bdsm

# 4. Set root password from environment variable
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

# 5. Start SSHD
CMD ["/usr/sbin/sshd", "-D"]