# Self Replicating Worm

⚠️ Do not run on any system or network you do not own and control. Unauthorized deployment may violate laws and institutional policies. You are solely responsible for lawful, ethical use.

## Overview
This sample malware shows three progressively more capable self-replicating programs:

- `FooVIrus.py`: Local single-host file infector for files ending in `.foo`.
- `FooWorm.py`: Network-aware worm that connects via SSH, looks for `.foo` files on a remote host, exfiltrates and re-uploads infected copies, and drops itself.
- `AbraWorm.py`: Polymorphic SSH worm that searches for files containing the string `abracadabra`, exfiltrates them, uploads a mutated copy of itself, and supports a debug mode for safe testing.

The code is intentionally simplified to make core concepts observable: discovery, infection logic, propagation, exfiltration, and basic anti-reinfection checks.

## Project Structure
- `FooVIrus.py` — local file infector that targets `.foo` files (no networking)
- `FooWorm.py` — SSH-based worm targeting `.foo` files on remote hosts
- `AbraWorm.py` — SSH/SCP polymorphic worm targeting files containing `abracadabra`
- `README.md` — this document

## Requirements
- Python 3.8+
- Linux-based hosts or containers for the target systems (for SSH-based runs)
- Python packages:
  - `paramiko` (SSH client)
  - `scp` (SCP over paramiko)

Install dependencies in an isolated environment:

```bash
python -m venv .venv
source .venv/bin/activate   # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install paramiko scp
```

## Configuration (Debug Mode)
Both `FooWorm.py` and `AbraWorm.py` implement a `debug = 1` mode to make testing predictable and self-contained:

- Uses fixed credentials: username `seed`, password `dees`.
- Uses fixed target IPs: `10.0.2.10` and `10.0.2.11`.
- Exfiltration server: `10.0.2.9` (also `seed/dees`).
- Halts after the first full iteration to prevent endless scanning.

Example topology (private, isolated network recommended):

- Host A (Operator): run the scripts from this repository.
- Host B (Target 1): IP `10.0.2.10`, SSH enabled, user `seed` / pass `dees`.
- Host C (Target 2): IP `10.0.2.11`, SSH enabled, user `seed` / pass `dees`.
- Host D (Exfil server): IP `10.0.2.9`, SSH enabled, user `seed` / pass `dees`.

Ensure SSH is running on all target hosts, accounts exist, and the network allows traffic among these IPs only.

## How Each Script Works

### FooVIrus.py (Local file infector)
Purpose: minimal self-replicating infector without networking.

- Reads its own first ~50 lines into memory (`virus_code`).
- Walks the filesystem (as coded: `/home/`) and targets files ending with `.foo`.
- Skips files that appear already infected (checks for a marker string containing `FooWorm`).
- Grants write permission (`chmod 777`) to ensure it can write the file.
- Prepends its own code and comments out the original file contents.

Run locally in a safe directory that contains test `.foo` files. Example:

```bash
python FooVIrus.py
```

Note: Paths are currently Linux-centric; adjust for your environment (or run inside a Linux VM).

### FooWorm.py (SSH worm for .foo files)
Purpose: remote discovery, infection, and exfiltration via SSH/SCP.

- In `debug = 1`:
  - Cycles over predefined users/passwords (`seed/dees`) and IPs (`10.0.2.10`, `10.0.2.11`).
  - Connects via SSH, runs `ls` to check if the target is already infected (looks for `FooWorm`).
  - Locates `.foo` files with `ls *.foo 2>/dev/null`.
  - If found: downloads them via SCP, then creates an infected version by prepending the worm code and commenting the original lines; uploads back and also uploads `FooWorm.py` itself to the target.
  - If files were collected, attempts to exfiltrate them to `10.0.2.9` via SCP.
- In `debug = 0`:
  - Username/password/IP generation becomes randomized. Do not use outside environments you explicitly control.

Run in debug mode (default in the provided code):

```bash
python FooWorm.py
```

### AbraWorm.py (Polymorphic SSH worm)
Purpose: polymorphism plus targeted file discovery by content.

- In `debug = 1`:
  - Uses fixed credentials (`seed/dees`) and IPs (`10.0.2.10`, `10.0.2.11`).
  - On a target host, avoids reinfection by checking for `AbraWorm` in `ls` output.
  - Searches for files containing the string `abracadabra` with `grep -ls abracadabra *`.
  - Downloads any matching files via SCP.
  - Creates a polymorphic variant of itself by inserting random newlines and random comment lines in a temp copy; uploads the modified file as `AbraWorm.py` to the target.
  - If files were collected, attempts to exfiltrate them to `10.0.2.9`.
- In `debug = 0`:
  - Randomized usernames/passwords/IPs are generated. Use only in environments you explicitly control.

Run in debug mode (default in the provided code):

```bash
python AbraWorm.py
```

## Creating Test Data
On the target hosts:

- For `FooWorm.py`/`FooVIrus.py`:
  ```bash
  echo "sample" > /home/seed/test1.foo
  echo "another" > /home/seed/docs/report.foo
  ```

- For `AbraWorm.py` (files containing `abracadabra`):
  ```bash
  echo "nothing here" > /home/seed/notes.txt
  echo "abracadabra magic" > /home/seed/secrets.txt
  ```

Ensure file permissions allow read/write for the test user.

## Operational Notes
- Default behavior for the SSH worms presumes password authentication is enabled on targets.
- Host key verification is disabled (`AutoAddPolicy`) for simplicity in this project.
- Timeouts are short (e.g., 5s) to keep runs responsive; adjust for your environment if needed.
- Exfiltration steps require the exfil server to be reachable and writable with the same credentials.

## Troubleshooting
- "Connection failed" or timeouts:
  - Verify IPs, SSH service status, credentials, and network connectivity.
  - Confirm you are running within the isolated lab network.
- "No files found":
  - Ensure the target host actually has `.foo` files (for `FooWorm.py`) or files containing `abracadabra` (for `AbraWorm.py`).
- Permission errors writing files:
  - Create test files under a user-writable directory and keep ownership consistent with the SSH user.
- Windows hosts:
  - These scripts target Linux paths and tools (`grep`, Unix permissions). Use Linux VMs or WSL for faithful behavior.

## Cleanup
- Delete any infected `.foo` or `abracadabra` files you created for testing.
- Remove uploaded worm scripts from target hosts (`FooWorm.py`, `AbraWorm.py`).
- Restore from snapshots if you took them before running tests (recommended).
- Disable or reset the test accounts and passwords used for this project.

## Ethics and Legal
This project is for defensive education: to understand how worms operate so you can detect, prevent, and respond. Never deploy code resembling this without explicit authorization and all necessary approvals.

## License
Educational use only. If you intend to redistribute or adapt, consult your instructor and institution policies and apply an appropriate license.
