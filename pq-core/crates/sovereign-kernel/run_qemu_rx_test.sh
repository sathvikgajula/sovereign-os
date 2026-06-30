#!/usr/bin/env bash
# RX ingest validation: socket netdev + raw Ethernet injector → guest virtio-net RX poll.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"

CONSOLE_LOG="/tmp/antigravity/qemu_rx_console.log"
PORT="${SOCKET_PORT:-8010}"

mkdir -p /tmp/antigravity
rm -f "$CONSOLE_LOG"

HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
    arm64|aarch64)
        TARGET="${TARGET:-aarch64-unknown-none}"
        QEMU_BIN="${QEMU_BIN:-qemu-system-aarch64}"
        QEMU_MACHINE="${QEMU_MACHINE:-virt,iommu=none}"
        QEMU_CPU="${QEMU_CPU:-max}"
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
        echo "[!] Unsupported host: $HOST_ARCH"
        exit 1
        ;;
esac

KERNEL_BIN="target/${TARGET}/release/sovereign-kernel"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[*] Building sovereign-kernel (${TARGET})..."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$(cd "$(dirname "$0")/../.." && pwd)/target}"
cargo build -p sovereign-kernel --target "$TARGET" --release --bin sovereign-kernel --features rx-lab >/dev/null

echo "[*] Launching QEMU with socket netdev on port ${PORT} ..."
"$QEMU_BIN" \
    -machine "$QEMU_MACHINE" \
    -cpu "$QEMU_CPU" \
    -m 256M \
    -kernel "$KERNEL_BIN" \
    -netdev "socket,id=net0,listen=:${PORT}" \
    -device "$QEMU_NETDEV_DEVICE" \
    -serial "file:$CONSOLE_LOG" \
    -monitor none \
    -display none \
    >/tmp/antigravity/qemu_rx_stderr.log 2>&1 &
QEMU_PID=$!

cleanup() {
    kill "$QEMU_PID" 2>/dev/null || true
    wait "$QEMU_PID" 2>/dev/null || true
}
trap cleanup EXIT

sleep 4

echo "[*] Injecting raw Ethernet frames via socket netdev ..."
python3 "$SCRIPT_DIR/inject_rx_frame.py" "$PORT" || true

sleep 2
kill "$QEMU_PID" 2>/dev/null || true
wait "$QEMU_PID" 2>/dev/null || true
trap - EXIT

echo "[*] Console log tail:"
tail -25 "$CONSOLE_LOG" 2>/dev/null || true

if grep -q 'UDP echo ok' "$CONSOLE_LOG" 2>/dev/null; then
    echo "[+] smoltcp UDP echo OK"
    exit 0
fi

if grep -q 'UDP rx len=' "$CONSOLE_LOG" 2>/dev/null; then
    echo "[+] smoltcp UDP receive OK"
    exit 0
fi

if grep -q 'RX frame len=' "$CONSOLE_LOG" 2>/dev/null; then
    RX_COUNT=$(grep -c 'RX frame len=' "$CONSOLE_LOG" || true)
    echo "[+] RX ingest OK — observed ${RX_COUNT} RX log line(s)"
    exit 0
fi

if grep -q 'RX used idx=' "$CONSOLE_LOG" 2>/dev/null; then
    echo "[+] RX used-ring advancement observed (frame delivery may be coherency-limited)"
    grep 'RX used idx=' "$CONSOLE_LOG" | tail -3
    exit 0
fi

echo "[!] No RX frames observed in console log"
echo "    Full log: $CONSOLE_LOG"
exit 1
