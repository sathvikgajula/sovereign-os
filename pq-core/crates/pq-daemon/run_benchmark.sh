#!/usr/bin/env bash

set -e

# Root check warning for tcpdump
if [ "$EUID" -ne 0 ]; then
  echo "[WARNING] This benchmark might fail if tcpdump requires root privileges to capture."
  echo "          If it fails, please run: sudo ./run_benchmark.sh"
fi

echo "[*] Initializing Sovereign OS v2.0-ULTRA Benchmark Harness"

# Setup directories
rm -rf /tmp/antigravity/node_9101
rm -rf /tmp/antigravity/node_9102
mkdir -p /tmp/antigravity/node_9101/input
mkdir -p /tmp/antigravity/node_9102/input
chmod 0700 /tmp/antigravity/node_9101
chmod 0700 /tmp/antigravity/node_9102

# Assert binary exists
if [ ! -f "target/release/pq-daemon" ]; then
    echo "[!] target/release/pq-daemon not found! Compiling..."
    cargo build --release -p pq-daemon
fi

# Detect loopback interface
IFACE="lo0"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    IFACE="lo"
fi

# Trap to ensure cleanup on error or interrupt
trap cleanup SIGINT SIGTERM

cleanup() {
    echo ""
    echo "[*] Terminating processes..."
    if [ -n "$PID_A" ]; then
        kill -15 "$PID_A" 2>/dev/null || true
    fi
    if [ -n "$PID_B" ]; then
        kill -15 "$PID_B" 2>/dev/null || true
    fi
    if [ -n "$TCPDUMP_PID" ]; then
        kill -15 "$TCPDUMP_PID" 2>/dev/null || true
    fi
    wait "$PID_A" "$PID_B" "$TCPDUMP_PID" 2>/dev/null || true
    
    echo "[*] Executing secure cryptographic wipe of ephemeral state..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        rm -P -R /tmp/antigravity/node_9101 2>/dev/null || true
        rm -P -R /tmp/antigravity/node_9102 2>/dev/null || true
    else
        find /tmp/antigravity/node_9101 -type f -exec shred -u {} \; 2>/dev/null || true
        find /tmp/antigravity/node_9102 -type f -exec shred -u {} \; 2>/dev/null || true
        rm -rf /tmp/antigravity/node_9101 /tmp/antigravity/node_9102 2>/dev/null || true
    fi
    echo "[*] Cleanup complete."
}

# 1. Start Capture
echo "[*] Starting tcpdump loopback capture on interface: $IFACE"
tcpdump -i "$IFACE" -w /tmp/antigravity/benchmark.pcap "udp and (port 9101 or port 9102)" > /dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 2

# 2. Launch Node A & B
echo "[*] Launching Node A (port 9101)..."
./target/release/pq-daemon --port 9101 --identity ALICE --test-live-fire > /tmp/antigravity/node_9101/sovereign.log 2>&1 &
PID_A=$!

echo "[*] Launching Node B (port 9102)..."
./target/release/pq-daemon --port 9102 --identity BOB --test-live-fire > /tmp/antigravity/node_9102/sovereign.log 2>&1 &
PID_B=$!

echo "[*] Nodes active. Node A PID: $PID_A | Node B PID: $PID_B"

# ────────────────────────────────────────────────────────────────
# Phase I: Idle Cover (90 seconds)
# ────────────────────────────────────────────────────────────────
echo "[*] Phase I (Idle Cover): Nodes pumping pure ChaCha20 AEP decoys. Sleeping for 90 seconds..."
sleep 90

# ────────────────────────────────────────────────────────────────
# Phase II: Payload Burst (90 seconds)
# ────────────────────────────────────────────────────────────────
echo "[*] Phase I complete. Injecting 100 cryptographic post-quantum shards into Node A..."
for i in {1..100}; do
    dd if=/dev/urandom of=/tmp/antigravity/node_9101/input/shard_$i.bin bs=512 count=1 2>/dev/null
done

echo "[*] Phase II (Payload Burst): Heavy active messaging active. Sleeping for 90 seconds..."
sleep 90

# ────────────────────────────────────────────────────────────────
# Shutdown and Analysis
# ────────────────────────────────────────────────────────────────
echo "[*] Phase II complete. Stopping benchmark..."

# Terminate nodes gracefully so logs and database commit cleanly
kill -15 "$PID_A" 2>/dev/null || true
kill -15 "$PID_B" 2>/dev/null || true
kill -15 "$TCPDUMP_PID" 2>/dev/null || true
wait "$PID_A" "$PID_B" "$TCPDUMP_PID" 2>/dev/null || true

# Run analysis before secure wipe
echo "[*] Launching statistical analysis engine..."
if [ -f "crates/pq-daemon/analyze_traffic.py" ]; then
    python3 crates/pq-daemon/analyze_traffic.py
elif [ -f "analyze_traffic.py" ]; then
    python3 analyze_traffic.py
else
    echo "[!] Analysis script analyze_traffic.py not found!"
fi

# Execute secure wipe
cleanup
