#!/bin/bash
# Nuclei scan through Tor with timeout and limited templates
# Usage: nuclei_tor_scan.sh <target_url> [output_file] [extra_args...]
#
# This script runs nuclei on the HOST where Tor is at 127.0.0.1:9050.
# Docker containers can read results from the shared /tmp volume.
#
# Key features:
# - Hard 5-minute timeout per nuclei invocation
# - Only scans high/critical severity templates (fast through Tor)
# - Rate-limited to 5 requests/second (Tor-friendly)
# - Single retry, no interactsh (avoids DNS callbacks through Tor)

set -euo pipefail

TARGET="${1:?Usage: nuclei_tor_scan.sh <target_url> [output_file] [extra_args...]}"
OUTPUT="${2:-/tmp/nuclei_tor_results.txt}"
shift 2 || true
EXTRA_ARGS="$@"
TIMEOUT=300  # 5 minutes max

echo "=== Nuclei Tor Scan ==="
echo "Target: $TARGET"
echo "Output: $OUTPUT"
echo "Timeout: ${TIMEOUT}s"
echo ""

# Verify Tor is running
echo "Checking Tor connectivity..."
if ! curl -s --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip --max-time 15 | grep -q "true"; then
    echo "ERROR: Tor is not running or not responding at 127.0.0.1:9050"
    echo "SCAN_FAILED: Tor not available" > "$OUTPUT"
    exit 1
fi
echo "Tor is running."

# Run nuclei with Tor proxy, limited templates, hard timeout
echo "Starting nuclei scan (timeout: ${TIMEOUT}s)..."
echo ""

timeout $TIMEOUT nuclei \
    -u "$TARGET" \
    -proxy socks5://127.0.0.1:9050 \
    -severity high,critical \
    -timeout 15 \
    -retries 1 \
    -no-interactsh \
    -rate-limit 5 \
    -c 10 \
    -silent \
    $EXTRA_ARGS \
    2>&1 | tee "$OUTPUT"

EXIT_CODE=${PIPESTATUS[0]}

echo ""
if [ $EXIT_CODE -eq 124 ]; then
    echo "SCAN_TIMEOUT: Nuclei scan timed out after ${TIMEOUT}s" >> "$OUTPUT"
    echo "Scan TIMED OUT after ${TIMEOUT}s"
elif [ $EXIT_CODE -eq 0 ]; then
    echo "Scan completed successfully."
else
    echo "Scan completed with exit code $EXIT_CODE"
fi

echo "SCAN_COMPLETE: exit=$EXIT_CODE output=$OUTPUT"
