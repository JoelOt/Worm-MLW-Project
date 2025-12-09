FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Actualizar repositorios y paquetes necesarios
RUN apt-get update && apt-get install -y \
    openssh-server \
    gcc \
    make \
    libssh-dev \
    && rm -rf /var/lib/apt/lists/*

# Crear directorio para SSH de manera segura
RUN mkdir -p /var/run/sshd

# Configurar usuario ubuntu (ya existe en la imagen base) con contraseña 'ubuntu'
RUN echo "ubuntu:ubuntu" | chpasswd && usermod -aG sudo ubuntu && usermod -s /bin/bash ubuntu

# Configurar SSH para permitir login con contraseña
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Exponer puerto SSH
EXPOSE 22

# Iniciar SSH
CMD ["/usr/sbin/sshd","-D"]
