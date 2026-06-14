# sovereign-kernel — Bare-Metal Microkernel (Phase C)

`#![no_std]` multi-arch QEMU target: VirtIO-net heartbeat egress + allocation-free 200ms metronome loop.

## Supported targets

| Host (`uname -m`) | Rust triple | QEMU |
|-------------------|-------------|------|
| `arm64` / `aarch64` | `aarch64-unknown-none` | `qemu-system-aarch64 -machine virt` |
| `x86_64` / `amd64` | `x86_64-unknown-none` | `qemu-system-x86_64 -machine microvm` (PVH note) |

## Quickstart — Live-Fire QEMU + PCAP Audit

From the `pq-core/` workspace root:

```bash
# Auto-detects host arch, builds the matching target, captures 30s of wire traffic
./crates/sovereign-kernel/run_qemu.sh

# Verify 512-byte uniformity + 200ms IPD cadence
python3 crates/sovereign-kernel/verify_bytes.py /tmp/antigravity/baremetal_heartbeat.pcap
```

### Manual builds

```bash
# Apple Silicon (native aarch64 bare-metal)
cargo build -p sovereign-kernel --target aarch64-unknown-none --release

# x86_64 bare-metal (includes PVH ELF note for microvm)
cargo build -p sovereign-kernel --target x86_64-unknown-none --release
```

### Manual QEMU (Apple Silicon)

```bash
qemu-system-aarch64 \
  -machine virt -cpu max -m 256M \
  -kernel target/aarch64-unknown-none/release/sovereign-kernel \
  -netdev user,id=net0 \
  -device virtio-net-device,netdev=net0 \
  -object filter-dump,id=f1,netdev=net0,file=/tmp/antigravity/baremetal_heartbeat.pcap \
  -nographic
```

## `run_qemu.sh` environment overrides

| Variable | Default | Description |
|----------|---------|-------------|
| `RUN_SEC` | `30` | Capture duration |
| `TARGET` | auto from `uname -m` | Rust target triple |
| `QEMU_BIN` | auto from `uname -m` | QEMU binary |
| `QEMU_MACHINE` | `virt` (arm64) / `microvm` (x86) | QEMU machine type |

## Architecture

| Module | Role |
|--------|------|
| `entry.rs` | Arch-specific stack init (`bare_start`) + `kernel_main` boot chain |
| `main.rs` | Bin-root `_start` → `entry::bare_start()` (rust-lld entry linkage) |
| `virtio/net.rs` | MMIO VirtIO-net TX virtqueue (`NetTx`) — scans high MMIO slots on `virt` |
| `timer.rs` | `CNTFRQ_EL0`-calibrated `MetronomeTimer` (aarch64) / TSC (x86) |
| `../sovereign-frame/metronome.rs` | Zero-alloc 512B / 200ms heartbeat loop |

## Linker scripts

- `linker-aarch64.ld` — load @ `0x40080000` (QEMU `virt` `-kernel`)
- `linker-x86_64.ld` — load @ `0x100000` + PVH note (`boot/mod.rs`)

Configured in `pq-core/.cargo/config.toml`.
