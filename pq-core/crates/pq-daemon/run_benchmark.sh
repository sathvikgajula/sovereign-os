#!/usr/bin/env bash

set -e

# Usage:
#   ./run_benchmark.sh              # single 3-minute trial (default)
#   ./run_benchmark.sh --multi-trial  # 3 trials + median aggregation

MULTI_TRIAL=0
if [ "${1:-}" = "--multi-trial" ]; then
  MULTI_TRIAL=3
  shift
fi

TRIAL_COUNT=1
if [ "$MULTI_TRIAL" -gt 0 ]; then
  TRIAL_COUNT=$MULTI_TRIAL
fi

TRIALS_DIR="/tmp/antigravity/trials"
ANALYZE_SCRIPT="crates/pq-daemon/analyze_traffic.py"
if [ ! -f "$ANALYZE_SCRIPT" ] && [ -f "analyze_traffic.py" ]; then
  ANALYZE_SCRIPT="analyze_traffic.py"
fi

# Root check warning for tcpdump
if [ "$EUID" -ne 0 ]; then
  echo "[WARNING] This benchmark might fail if tcpdump requires root privileges to capture."
  echo "          If it fails, please run: sudo ./run_benchmark.sh"
fi

echo "[*] Initializing Sovereign OS v2.0-ULTRA Benchmark Harness"
if [ "$TRIAL_COUNT" -gt 1 ]; then
  echo "[*] Multi-trial mode: ${TRIAL_COUNT} iterations → ${TRIALS_DIR}"
  mkdir -p "$TRIALS_DIR"
fi

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

PID_A=""
PID_B=""
TCPDUMP_PID=""

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
    PID_A=""
    PID_B=""
    TCPDUMP_PID=""

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

trap cleanup SIGINT SIGTERM

run_analysis() {
    local trial_num="$1"
    local output_path="$2"
    local no_figures="$3"

    echo "[*] Launching statistical analysis engine..."
    if [ ! -f "$ANALYZE_SCRIPT" ]; then
        echo "[!] Analysis script analyze_traffic.py not found!"
        return 1
    fi

    local args=(python3 "$ANALYZE_SCRIPT")
    if [ -n "$output_path" ]; then
        args+=(--output "$output_path")
    fi
    if [ "$no_figures" = "1" ]; then
        args+=(--no-figures)
    fi
    if [ -n "$trial_num" ]; then
        args+=(--trial-id "$trial_num")
    fi
    "${args[@]}"
}

run_single_trial() {
    local trial_num="$1"

    rm -rf /tmp/antigravity/node_9101
    rm -rf /tmp/antigravity/node_9102
    mkdir -p /tmp/antigravity/node_9101/input
    mkdir -p /tmp/antigravity/node_9102/input
    chmod 0700 /tmp/antigravity/node_9101
    chmod 0700 /tmp/antigravity/node_9102

    echo "[*] Starting tcpdump loopback capture on interface: $IFACE"
    tcpdump -i "$IFACE" -w /tmp/antigravity/benchmark.pcap "udp and (port 9101 or port 9102)" > /dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 2

    echo "[*] Launching Node A (port 9101)..."
    ./target/release/pq-daemon --port 9101 --identity ALICE --test-live-fire > /tmp/antigravity/node_9101/sovereign.log 2>&1 &
    PID_A=$!

    echo "[*] Launching Node B (port 9102)..."
    ./target/release/pq-daemon --port 9102 --identity BOB --test-live-fire > /tmp/antigravity/node_9102/sovereign.log 2>&1 &
    PID_B=$!

    echo "[*] Nodes active. Node A PID: $PID_A | Node B PID: $PID_B"

    echo "[*] Phase I (Idle Cover): Nodes pumping pure ChaCha20 AEP decoys. Sleeping for 90 seconds..."
    sleep 90

    echo "[*] Phase I complete. Injecting 100 cryptographic post-quantum shards into Node A..."
    for i in {1..100}; do
        dd if=/dev/urandom of=/tmp/antigravity/node_9101/input/shard_$i.bin bs=512 count=1 2>/dev/null
    done

    echo "[*] Phase II (Payload Burst): Heavy active messaging active. Sleeping for 90 seconds..."
    sleep 90

    echo "[*] Phase II complete. Stopping benchmark..."
    kill -15 "$PID_A" 2>/dev/null || true
    kill -15 "$PID_B" 2>/dev/null || true
    kill -15 "$TCPDUMP_PID" 2>/dev/null || true
    wait "$PID_A" "$PID_B" "$TCPDUMP_PID" 2>/dev/null || true
    PID_A=""
    PID_B=""
    TCPDUMP_PID=""
}

for trial in $(seq 1 "$TRIAL_COUNT"); do
    if [ "$TRIAL_COUNT" -gt 1 ]; then
        echo ""
        echo "════════════════════════════════════════════════════════════════"
        echo "  TRIAL ${trial}/${TRIAL_COUNT}"
        echo "════════════════════════════════════════════════════════════════"
    fi

    run_single_trial "$trial"

    if [ "$TRIAL_COUNT" -gt 1 ]; then
        trial_file="${TRIALS_DIR}/simulation_metrics_$(printf '%03d' "$trial").json"
        run_analysis "$trial" "$trial_file" "1"
    else
        run_analysis "" "" "0"
    fi

    cleanup
done

if [ "$TRIAL_COUNT" -gt 1 ]; then
    echo ""
    echo "[*] Aggregating ${TRIAL_COUNT} trials for publication-ready figures..."
    python3 "$ANALYZE_SCRIPT" --aggregate "$TRIALS_DIR"
fi
