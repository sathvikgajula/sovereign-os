#!/usr/bin/env bash
# QEMU bare-metal launch harness with live PCAP capture (Track 3).
#
# Auto-detects host architecture and routes to the correct Rust target + QEMU binary.
#
# Usage (from pq-core/):
#   ./crates/sovereign-kernel/run_qemu.sh
#
# After capture, verify:
#   python3 crates/sovereign-kernel/verify_bytes.py

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

PCAP_OUT="/tmp/antigravity/baremetal_heartbeat.pcap"
CONSOLE_LOG="/tmp/antigravity/qemu_console.log"
RUN_SEC="${RUN_SEC:-30}"

mkdir -p /tmp/antigravity

# ── Portable timeout (macOS lacks GNU timeout) ──────────────────────────────
run_with_timeout() {
    local secs="$1"
    shift
    if command -v timeout >/dev/null 2>&1; then
        timeout "$secs" "$@"
        return $?
    fi
    if command -v gtimeout >/dev/null 2>&1; then
        gtimeout "$secs" "$@"
        return $?
    fi
    # macOS fallback: background killer + wait (perl alarm does not reap QEMU children)
    "$@" &
    local child=$!
    (
        sleep "$secs"
        kill "$child" 2>/dev/null || true
    ) &
    local killer=$!
    wait "$child" 2>/dev/null
    local rc=$?
    kill "$killer" 2>/dev/null || true
    return $rc
}

# ── Host architecture → Rust triple + QEMU invocation ───────────────────────
HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
    arm64|aarch64)
        TARGET="${TARGET:-aarch64-unknown-none}"
        QEMU_BIN="${QEMU_BIN:-qemu-system-aarch64}"
        QEMU_MACHINE="${QEMU_MACHINE:-virt,iommu=none}"
        QEMU_CPU="${QEMU_CPU:-max}"
        # dma_as=sysmem is not exposed on QEMU 11 virtio-net-device; iommu=none + iommu_platform=off
        # forces sysmem DMA on the virt machine for Apple Silicon cache coherency.
        QEMU_NETDEV_DEVICE="${QEMU_NETDEV_DEVICE:-virtio-net-device,netdev=net0,iommu_platform=off}"
        ;;
    x86_64|amd64)
        TARGET="${TARGET:-x86_64-unknown-none}"
        QEMU_BIN="${QEMU_BIN:-qemu-system-x86_64}"
        QEMU_MACHINE="${QEMU_MACHINE:-microvm}"
        QEMU_CPU="${QEMU_CPU:-max}"
        QEMU_NETDEV_DEVICE="${QEMU_NETDEV_DEVICE:-virtio-net-device,netdev=net0}"
        ;;
    *)
        echo "[!] Unsupported host architecture: $HOST_ARCH"
        echo "    Override with TARGET= and QEMU_BIN= if cross-emulating."
        exit 1
        ;;
esac

KERNEL_BIN="target/${TARGET}/release/sovereign-kernel"

echo "────────────────────────────────────────────────────────────────"
echo "  SOVEREIGN BARE-METAL QEMU HARNESS — Track 3"
echo "────────────────────────────────────────────────────────────────"
echo "[*] Host arch:   $HOST_ARCH"
echo "[*] Rust target: $TARGET"
echo "[*] QEMU binary: $QEMU_BIN"
echo "[*] Machine:     $QEMU_MACHINE"
echo "[*] Capture:     ${RUN_SEC}s → $PCAP_OUT"
echo "[*] Console log: $CONSOLE_LOG"
echo "────────────────────────────────────────────────────────────────"

echo "[*] Building sovereign-kernel (${TARGET})..."
if ! cargo build -p sovereign-kernel --target "$TARGET" --release 2>&1 | tail -8; then
    echo "[!] Build failed for ${TARGET}"
    exit 1
fi

if [ ! -f "$KERNEL_BIN" ]; then
    echo "[!] Kernel binary not found: $KERNEL_BIN"
    exit 1
fi

echo "[*] Kernel ELF: $KERNEL_BIN ($(wc -c < "$KERNEL_BIN" | tr -d ' ') bytes)"
rm -f "$PCAP_OUT" "$CONSOLE_LOG"

echo "[*] Launching QEMU..."
set +e
run_with_timeout "$RUN_SEC" "$QEMU_BIN" \
    -machine "$QEMU_MACHINE" \
    -cpu "$QEMU_CPU" \
    -m 256M \
    -kernel "$KERNEL_BIN" \
    -netdev user,id=net0 \
    -device "$QEMU_NETDEV_DEVICE" \
    -object "filter-dump,id=f1,netdev=net0,file=$PCAP_OUT" \
    -serial "file:$CONSOLE_LOG" \
    -monitor none \
    -display none \
    2>/tmp/antigravity/qemu_stderr.log
qemu_rc=$?
set -e

if [ -s /tmp/antigravity/qemu_stderr.log ]; then
    tail -5 /tmp/antigravity/qemu_stderr.log | sed 's/^/    /'
fi

if [ "$qemu_rc" -ne 0 ] && [ "$qemu_rc" -ne 124 ] && [ "$qemu_rc" -ne 142 ]; then
    echo "[!] QEMU exited with code $qemu_rc"
fi

if [ -f "$PCAP_OUT" ]; then
    echo "[*] PCAP written: $PCAP_OUT ($(wc -c < "$PCAP_OUT" | tr -d ' ') bytes)"
    python3 crates/sovereign-kernel/verify_bytes.py "$PCAP_OUT" "$CONSOLE_LOG" || true
else
    echo "[!] No PCAP produced — kernel may not have reached virtio TX."
    echo "    Try: RUN_SEC=60 ./crates/sovereign-kernel/run_qemu.sh"
    echo "    QEMU log: /tmp/antigravity/qemu_stderr.log"
    exit 1
fi
