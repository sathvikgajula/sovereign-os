//! Static smoltcp Interface + UDP echo for bare-metal bring-up.

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet, SocketStorage};
use smoltcp::socket::udp;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address};

use crate::driver::Timer;
use crate::timer::TscTimer;
use crate::uart;
use crate::virtio::VirtioNet;

use super::device::{self, VirtioDevice};

/// Guest IPv4 on QEMU user/slirp and socket netdev inject scripts.
const GUEST_IP: Ipv4Address = Ipv4Address::new(10, 0, 2, 15);
const GUEST_MASK: u8 = 24;
const GATEWAY: Ipv4Address = Ipv4Address::new(10, 0, 2, 2);
/// UDP echo port (`inject_rx_frame.py` targets port 9).
const UDP_ECHO_PORT: u16 = 9;

const SOCKET_COUNT: usize = 1;

static mut SOCKET_STORAGE: [SocketStorage; SOCKET_COUNT] = [SocketStorage::EMPTY; SOCKET_COUNT];
static mut RX_META: [udp::PacketMetadata; 4] = [udp::PacketMetadata::EMPTY; 4];
static mut TX_META: [udp::PacketMetadata; 4] = [udp::PacketMetadata::EMPTY; 4];
static mut RX_PACKET_BUF: [u8; 2048] = [0u8; 2048];
static mut TX_PACKET_BUF: [u8; 2048] = [0u8; 2048];

static mut DEVICE: Option<VirtioDevice<'static>> = None;
static mut IFACE: Option<Interface> = None;
static mut SOCKETS: Option<SocketSet<'static>> = None;
static mut UDP_HANDLE: Option<SocketHandle> = None;

/// Build Interface + UDP socket bound to [`UDP_ECHO_PORT`].
pub unsafe fn init_stack(net: &'static VirtioNet) {
    let mac = EthernetAddress(net.eth_mac());
    let mut config = Config::new(HardwareAddress::Ethernet(mac));
    config.random_seed = 0x5254_4F53;
    let mut device = VirtioDevice::new(net);
    let mut iface = Interface::new(config, &mut device, Instant::ZERO);
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(GUEST_IP), GUEST_MASK));
    });
    let _ = iface.routes_mut().add_default_ipv4_route(GATEWAY);

    let rx_meta = &mut *core::ptr::addr_of_mut!(RX_META);
    let tx_meta = &mut *core::ptr::addr_of_mut!(TX_META);
    let rx_payload = &mut *core::ptr::addr_of_mut!(RX_PACKET_BUF);
    let tx_payload = &mut *core::ptr::addr_of_mut!(TX_PACKET_BUF);
    let rx_buf = udp::PacketBuffer::new(&mut rx_meta[..], &mut rx_payload[..]);
    let tx_buf = udp::PacketBuffer::new(&mut tx_meta[..], &mut tx_payload[..]);
    let udp_socket = udp::Socket::new(rx_buf, tx_buf);
    let storage = &mut *core::ptr::addr_of_mut!(SOCKET_STORAGE);
    let mut sockets = SocketSet::new(&mut storage[..]);
    let handle = sockets.add(udp_socket);
    let _ = sockets
        .get_mut::<udp::Socket>(handle)
        .bind((GUEST_IP, UDP_ECHO_PORT));

    DEVICE = Some(device);
    IFACE = Some(iface);
    SOCKETS = Some(sockets);
    UDP_HANDLE = Some(handle);
    uart::write_str("smoltcp UDP echo :9 @10.0.2.15\n");
}

/// Inject a synthetic IPv4/UDP frame into the device RX staging buffer (lab only).
pub unsafe fn inject_udp_selftest() {
    let dst_mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    let src_mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x57];
    let payload = b"sovereign-smoltcp-selftest";
    let mut frame = [0u8; 128];
    let mut n = 0usize;
    frame[n..n + 6].copy_from_slice(&dst_mac);
    n += 6;
    frame[n..n + 6].copy_from_slice(&src_mac);
    n += 6;
    frame[n..n + 2].copy_from_slice(&[0x08, 0x00]);
    n += 2;
    let ip_start = n;
    frame[n] = 0x45;
    frame[n + 1] = 0;
    let ip_hdr_len = 20usize;
    let udp_len = 8 + payload.len();
    let ip_total = (ip_hdr_len + udp_len) as u16;
    frame[n + 2..n + 4].copy_from_slice(&ip_total.to_be_bytes());
    frame[n + 6..n + 8].copy_from_slice(&0x4000u16.to_be_bytes());
    frame[n + 8] = 64;
    frame[n + 9] = 17;
    frame[n + 12..n + 16].copy_from_slice(&[10, 0, 2, 2]);
    frame[n + 16..n + 20].copy_from_slice(&[10, 0, 2, 15]);
    let mut sum = 0u32;
    for i in (ip_start..ip_start + ip_hdr_len).step_by(2) {
        sum += u16::from_be_bytes([frame[i], frame[i + 1]]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let csum = !(sum as u16);
    frame[ip_start + 10..ip_start + 12].copy_from_slice(&csum.to_be_bytes());
    n += ip_hdr_len;
    frame[n..n + 2].copy_from_slice(&12345u16.to_be_bytes());
    frame[n + 2..n + 4].copy_from_slice(&9u16.to_be_bytes());
    frame[n + 4..n + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    n += 8;
    frame[n..n + payload.len()].copy_from_slice(payload);
    n += payload.len();

    device::stage_rx_frame(&frame[..n]);
    if let Some(dev) = DEVICE.as_mut() {
        dev.set_rx_ready(true);
    }
}

/// Poll virtio RX, smoltcp iface, and echo UDP payloads.
pub unsafe fn poll_stack(timer: &TscTimer) {
    let device = DEVICE.as_mut().unwrap();
    let iface = IFACE.as_mut().unwrap();
    let sockets = SOCKETS.as_mut().unwrap();
    let handle = UDP_HANDLE.unwrap();

    device.poll_virtio();
    let micros = (timer.monotonic_ns() / 1000) as i64;
    let timestamp = Instant::from_micros(micros);
    iface.poll(timestamp, device, sockets);

    let socket = sockets.get_mut::<udp::Socket>(handle);
    if !socket.can_recv() {
        return;
    }
    let mut echo_buf = [0u8; 512];
    let echo_len;
    let remote;
    match socket.recv() {
        Ok((payload, endpoint)) => {
            echo_len = payload.len().min(512);
            echo_buf[..echo_len].copy_from_slice(&payload[..echo_len]);
            remote = endpoint;
            uart::write_str("UDP rx len=");
            uart::write_u16(echo_len as u16);
            uart::write_str(" from port=");
            uart::write_u16(remote.endpoint.port);
            uart::putc(b'\n');
        }
        Err(_) => return,
    }
    if socket.send_slice(&echo_buf[..echo_len], remote).is_ok() {
        uart::write_str("UDP echo ok\n");
        iface.poll(timestamp, device, sockets);
    }
}
