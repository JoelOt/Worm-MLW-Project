#!/bin/bash
# Automated shadow file cracking script using John the Ripper

if [ -z "$1" ]; then
    echo "Usage: $0 <shadow_file> [wordlist]"
    echo "Example: $0 extracted_shadow /usr/share/wordlists/rockyou.txt"
    exit 1
fi

SHADOW_FILE="$1"
WORDLIST="${2:-/usr/share/wordlists/rockyou.txt}"

echo "[*] Shadow File Cracking Script"
echo "=================================="
echo ""

# Check if shadow file exists
if [ ! -f "$SHADOW_FILE" ]; then
    echo "[-] Error: Shadow file '$SHADOW_FILE' not found"
    exit 1
fi

# Check if John the Ripper is installed
if ! command -v john &> /dev/null; then
    echo "[-] Error: John the Ripper not found"
    echo ""
    echo "[*] Installation instructions:"
    echo "    macOS:    brew install john-jumbo"
    echo "    Ubuntu:   sudo apt-get install john"
    echo "    Or download from: https://www.openwall.com/john/"
    exit 1
fi

echo "[+] John the Ripper found: $(john --version 2>&1 | head -1)"
echo ""

# Check if wordlist exists
if [ ! -f "$WORDLIST" ]; then
    echo "[-] Warning: Wordlist '$WORDLIST' not found"
    echo "[*] Using default wordlist generation instead"
    WORDLIST_OPTION=""
else
    echo "[+] Using wordlist: $WORDLIST"
    WORDLIST_OPTION="--wordlist=$WORDLIST"
fi

# Check for passwd file (for unshadow) - look in same directory
SHADOW_DIR=$(dirname "$SHADOW_FILE")
SHADOW_BASE=$(basename "$SHADOW_FILE")
PASSWD_FILE="${SHADOW_FILE%_shadow*}_passwd"
if [ ! -f "$PASSWD_FILE" ] && [ -f "${SHADOW_DIR}/passwd" ]; then
    PASSWD_FILE="${SHADOW_DIR}/passwd"
fi
if [ -f "$PASSWD_FILE" ]; then
    echo "[*] Found matching passwd file: $PASSWD_FILE"
    echo "[*] Combining with unshadow..."
    COMBINED_FILE="${SHADOW_FILE}.unshadow"
    if command -v unshadow &> /dev/null; then
        unshadow "$PASSWD_FILE" "$SHADOW_FILE" > "$COMBINED_FILE"
        SHADOW_FILE="$COMBINED_FILE"
        echo "[+] Created combined file: $COMBINED_FILE"
    fi
fi

# Show file statistics
echo ""
echo "[*] Analyzing shadow file..."
echo "    File: $SHADOW_FILE"
echo "    Size: $(du -h "$SHADOW_FILE" | cut -f1)"
echo "    Entries with hashes: $(grep -c ':\$' "$SHADOW_FILE" 2>/dev/null || echo 0)"

# Extract hash types
echo ""
echo "[*] Hash types detected:"
grep ':\$' "$SHADOW_FILE" 2>/dev/null | cut -d: -f2 | cut -d$ -f2 | sort -u | while read type; do
    case "$type" in
        1) echo "    \$1\$ = MD5 (old, weak)" ;;
        5) echo "    \$5\$ = SHA-256" ;;
        6) echo "    \$6\$ = SHA-512 (modern Linux)" ;;
        2a|2b|2y) echo "    \$${type}\$ = bcrypt" ;;
        *) echo "    \$${type}\$ = Type $type" ;;
    esac
done

echo ""
echo "[*] Starting password cracking..."
echo "[*] Press Ctrl+C to stop and show partial results"
echo ""

# Clear previous John session (remove pot file if exists)
POT_FILE="$HOME/.john/john.pot"
if [ -f "$POT_FILE" ]; then
    echo "[*] Clearing previous cracking session..."
    rm -f "$POT_FILE" 2>/dev/null
fi

# Run John the Ripper
echo "[*] Cracking passwords (this may take a while)..."
if [ -n "$WORDLIST_OPTION" ]; then
    # Use wordlist + rules for better results
    john --format=crypt $WORDLIST_OPTION --rules "$SHADOW_FILE" &
else
    # Use incremental mode (slower but thorough)
    john --format=crypt --incremental "$SHADOW_FILE" &
fi

JOHN_PID=$!

# Show progress periodically
while kill -0 $JOHN_PID 2>/dev/null; do
    sleep 10
    echo "[*] Still cracking... (Press Ctrl+C to stop and show results)"
    john --show --format=crypt "$SHADOW_FILE" 2>/dev/null | grep -q ':' && break
done

# Function to show results and exit
show_results() {
    echo ""
    echo "[*] Stopping John the Ripper..."
    kill $JOHN_PID 2>/dev/null
    wait $JOHN_PID 2>/dev/null
    
    echo ""
    echo "[*] Cracking Results:"
    echo "===================="
    john --show --format=crypt "$SHADOW_FILE"
    
    CRACKED_COUNT=$(john --show --format=crypt "$SHADOW_FILE" 2>/dev/null | grep -c '^[^:]*:' || echo 0)
    if [ "$CRACKED_COUNT" -gt 0 ]; then
        echo ""
        echo "[+] Successfully cracked $CRACKED_COUNT password(s)!"
    else
        echo ""
        echo "[-] No passwords cracked yet. Try:"
        echo "    - Using a different/larger wordlist"
        echo "    - Running longer: john --format=crypt $WORDLIST_OPTION $SHADOW_FILE"
        echo "    - Using Hashcat for GPU acceleration"
    fi
}

# Trap Ctrl+C to show results
trap show_results INT TERM

# Wait for John to finish or be interrupted
wait $JOHN_PID 2>/dev/null
show_results