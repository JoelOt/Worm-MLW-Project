FROM kalilinux/kali-rolling
# Red Team Tools
# - python3: For your C2 server and exploit scripts
# - curl/wget: For testing downloads
# - net-tools/iputils-ping: For 'ifconfig' and 'ping' (network discovery)
# - nano/vim: For editing scripts inside the container
# - git: Just in case
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-requests \
    curl \
    wget \
    net-tools \
    iputils-ping \
    nano \
    git \
    john \
    && rm -rf /var/lib/apt/lists/*