#!/usr/bin/env bash
# UI Chaos & Telemetry Stress Tester (Track 1)
# Hammers $HOME/.sovereign with shard I/O + SQLite while the Tauri dashboard runs.
#
# Usage:
#   Terminal A: cd crates/pq-dashboard && npm run tauri dev
#   Terminal B: ./crates/pq-dashboard/run_chaos_load.sh
#
# Watch FlatlineChart for clock_skew_us flatline (no scheduler bleed spikes).

set -euo pipefail

DURATION_SEC="${DURATION_SEC:-120}"
CHAOS_ROOT="${SOVEREIGN_CHAOS_ROOT:-$HOME/.sovereign/chaos_lab}"
SHARD_DIR="$CHAOS_ROOT/shards"
SQLITE_DB="$CHAOS_ROOT/chaos_stress.db"
CYCLE_MS="${CYCLE_MS:-50}"

mkdir -p "$SHARD_DIR"
chmod 0700 "$CHAOS_ROOT" "$SHARD_DIR" 2>/dev/null || true

echo "────────────────────────────────────────────────────────────────"
echo "  SOVEREIGN UI CHAOS LOAD — Track 1 Telemetry Stress Harness"
echo "────────────────────────────────────────────────────────────────"
echo "[*] Chaos root:     $CHAOS_ROOT"
echo "[*] Duration:       ${DURATION_SEC}s"
echo "[*] Cycle interval: ${CYCLE_MS}ms"
echo "[*] Verify: FlatlineChart clock_skew_us stays near 0µs in Terminal A"
echo "────────────────────────────────────────────────────────────────"

cleanup() {
    echo ""
    echo "[*] Chaos harness stopping — tearing down background workers..."
    for pid in $(jobs -p); do
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    echo "[*] Cleanup complete."
}
trap cleanup EXIT INT TERM

# ── Background SQLite hammer (isolated chaos DB, not production node DB) ──
sqlite_hammer() {
    python3 - "$SQLITE_DB" <<'PY'
import os, random, sqlite3, sys, time

db = sys.argv[1]
conn = sqlite3.connect(db)
conn.execute("PRAGMA journal_mode=WAL")
conn.execute("PRAGMA wal_autocheckpoint=0")
conn.execute(
    "CREATE TABLE IF NOT EXISTS chaos_shards ("
    "  id INTEGER PRIMARY KEY, payload BLOB, updated_at REAL)"
)
conn.commit()

while True:
    try:
        blob = os.urandom(512)
        conn.execute(
            "INSERT OR REPLACE INTO chaos_shards (id, payload, updated_at) VALUES (?,?,?)",
            (random.randint(1, 500), blob, time.time()),
        )
        conn.execute("SELECT COUNT(*), AVG(length(payload)) FROM chaos_shards").fetchone()
        conn.execute(
            "DELETE FROM chaos_shards WHERE id IN "
            "(SELECT id FROM chaos_shards ORDER BY RANDOM() LIMIT 5)"
        )
        conn.commit()
    except Exception:
        pass
PY
}

# ── Background mock mesh worker (rapid file create/write/delete) ──
shard_churn() {
    local dir="$1"
    while true; do
        for i in $(seq 1 25); do
            local f="$dir/shard_${RANDOM}_${i}.bin"
            dd if=/dev/urandom of="$f" bs=512 count=1 2>/dev/null || true
            echo "chaos:$RANDOM" >>"$f" 2>/dev/null || true
            rm -f "$f" 2>/dev/null || true
        done
        # Occasional directory sweep
        find "$dir" -name 'shard_*.bin' -mmin +1 -delete 2>/dev/null || true
        sleep 0.05
    done
}

sqlite_hammer &
SQL_PID=$!
shard_churn "$SHARD_DIR" &
SHARD_PID=$!

echo "[*] SQLite hammer PID: $SQL_PID"
echo "[*] Shard churn PID:   $SHARD_PID"
echo "[*] Chaos load active for ${DURATION_SEC}s..."

START=$(date +%s)
CYCLES=0

while true; do
    NOW=$(date +%s)
    ELAPSED=$((NOW - START))
    if [ "$ELAPSED" -ge "$DURATION_SEC" ]; then
        break
    fi

    # Main loop: burst create/modify/delete hundreds of dummy shards per cycle
    for i in $(seq 1 100); do
        F="$SHARD_DIR/burst_${CYCLES}_${i}.bin"
        dd if=/dev/urandom of="$F" bs=512 count=1 2>/dev/null || true
        # modify
        printf '\xA5' | dd of="$F" bs=1 count=1 conv=notrunc 2>/dev/null || true
    done
    # delete half
    for f in $(ls "$SHARD_DIR"/burst_${CYCLES}_*.bin 2>/dev/null | head -50); do
        rm -f "$f" 2>/dev/null || true
    done

    CYCLES=$((CYCLES + 1))
  if [ $((CYCLES % 20)) -eq 0 ]; then
        echo "[*] cycle=$CYCLES elapsed=${ELAPSED}s shards=$(find "$SHARD_DIR" -type f 2>/dev/null | wc -l | tr -d ' ')"
    fi
    sleep "$(awk "BEGIN {print $CYCLE_MS/1000}")"
done

echo ""
echo "================================================================"
echo "  CHAOS LOAD COMPLETE"
echo "================================================================"
echo "[*] Total burst cycles: $CYCLES"
echo "[*] Manual UI audit:"
echo "    1. FlatlineChart clock_skew_us timeline — no µs spikes"
echo "    2. TerminalLog — telemetry_tick lines at ~4 Hz"
echo "    3. VisualShardCache — queue depth updates without UI freeze"
echo "================================================================"
