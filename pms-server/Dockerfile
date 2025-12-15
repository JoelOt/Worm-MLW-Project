FROM node:22
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-requests \
    openssh-client \
    curl \
    wget \
    net-tools \
    iputils-ping \
    nano \
    git \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json ./
RUN npm install
COPY . .
RUN chown -R node:node /app
USER node
EXPOSE 3000
CMD ["npm", "run", "dev"]