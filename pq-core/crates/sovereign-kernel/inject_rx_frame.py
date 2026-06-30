#!/usr/bin/env python3
"""Inject a minimal Ethernet/IPv4/UDP frame into QEMU socket netdev (raw L2)."""
import socket
import struct
import sys
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8010
# Default virtio-net MAC from QEMU (matches console log).
DST_MAC = bytes.fromhex("525400123456")
BROADCAST = bytes.fromhex("ffffffffffff")
SRC_MAC = bytes.fromhex("525400123457")

def build_udp_frame(payload: bytes) -> bytes:
    eth = DST_MAC + SRC_MAC + b"\x08\x00"
    # IPv4 header (20 bytes) + UDP (8) + payload
    ip_total = 20 + 8 + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, ip_total, 0x1337, 0, 64, 17, 0,
        socket.inet_aton("10.0.2.2"), socket.inet_aton("10.0.2.15"))
    udp = struct.pack("!HHHH", 12345, 9, 8 + len(payload), 0)
    return eth + ip + udp + payload

def main() -> int:
    payload = b"sovereign-rx-socket-probe"
    for attempt in range(30):
        try:
            s = socket.create_connection(("127.0.0.1", PORT), timeout=2)
            s.sendall(build_udp_frame(payload))
            s.sendall(build_udp_frame(payload))  # unicast
            # Broadcast ARP-flavored probe (minimal eth frame)
            eth = BROADCAST + SRC_MAC + b"\x08\x06" + b"\x00" * 28
            s.sendall(eth)
            s.close()
            print(f"[+] Sent frames on attempt {attempt + 1}")
            time.sleep(0.25)
        except OSError as e:
            print(f"[!] Attempt {attempt + 1}: {e}", file=sys.stderr)
            time.sleep(0.5)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
