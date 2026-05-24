#!/usr/bin/env bash

set -e

# Root-Gate Check
if [ "$EUID" -ne 0 ]; then
  echo "[WARNING] This simulation is running without root privileges."
  echo "          Mach real-time thread policies and core affinity may fail (kern_return != 0)."
fi

echo "[*] Initializing Sovereign OS v2.0-ULTRA Simulation Harness"

# Trap for graceful shutdown and secure wipe
trap cleanup SIGINT SIGTERM

cleanup() {
    echo ""
    echo "[*] Caught signal, initiating graceful shutdown..."
    
    # Kill background PIDs gracefully
    if [ -n "$PID_A" ]; then
        kill -15 "$PID_A" 2>/dev/null || true
    fi
    if [ -n "$PID_B" ]; then
        kill -15 "$PID_B" 2>/dev/null || true
    fi
    
    # Wait for WAL flush and process exit
    wait "$PID_A" "$PID_B" 2>/dev/null || true
    
    echo "[*] Executing secure 3-pass cryptographic wipe on ephemeral state..."
    # macOS secure delete
    rm -P -R /tmp/antigravity/node_9101 2>/dev/null || true
    rm -P -R /tmp/antigravity/node_9102 2>/dev/null || true
    
    echo "[*] Cleaned up cleanly."
    exit 0
}

# 1. Clean out stale directories
rm -rf /tmp/antigravity/node_9101
rm -rf /tmp/antigravity/node_9102
mkdir -p /tmp/antigravity/node_9101
mkdir -p /tmp/antigravity/node_9102
chmod 0700 /tmp/antigravity/node_9101
chmod 0700 /tmp/antigravity/node_9102

# Assert binary exists
if [ ! -f "target/release/pq-daemon" ]; then
    echo "[!] target/release/pq-daemon not found! Compilation failed or missing."
    exit 1
fi

echo "[*] Launching Node A (The Anchor)..."
# We redirect stdout and stderr to the sovereign.log file so our telemetry appears there
./target/release/pq-daemon --port 9052 --identity ALICE --test-live-fire > /tmp/antigravity/node_9101/sovereign.log 2>&1 &
PID_A=$!

echo "[*] Launching Node B (The Peer)..."
./target/release/pq-daemon --port 9053 --identity BOB --test-live-fire > /tmp/antigravity/node_9102/sovereign.log 2>&1 &
PID_B=$!

echo "[*] Nodes active. Node A PID: $PID_A | Node B PID: $PID_B"
echo "[*] Tailing Node A Telemetry (Ctrl+C to terminate)..."
echo "───────────────────────────────────────────────────────"

# 2. Pipe Node A's real-time logs straight to the terminal
tail -f /tmp/antigravity/node_9101/sovereign.log &
TAIL_PID=$!

# Wait indefinitely for SIGINT
wait $PID_A $PID_B
