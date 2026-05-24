pub mod socket;
pub mod pending;
pub mod metronome;

use std::net::{UdpSocket, SocketAddr};
use std::os::unix::io::AsRawFd;
use tracing::{info, warn};

#[cfg(target_os = "linux")]
use libc::{SO_TIMESTAMPING, SO_TXTIME};

pub struct PhysicalBridge {
    socket: UdpSocket,
}

impl PhysicalBridge {
    pub fn new(port: u16) -> anyhow::Result<Self> {
        let socket = UdpSocket::bind(format!("0.0.0.0:{}", port))?;
        let fd = socket.as_raw_fd();

        #[cfg(target_os = "linux")]
        {
            // 1. SO_TIMESTAMPING (MAC-layer PTP timestamps)
            let flags = libc::SOF_TIMESTAMPING_TX_HARDWARE 
                      | libc::SOF_TIMESTAMPING_RX_HARDWARE 
                      | libc::SOF_TIMESTAMPING_RAW_HARDWARE;
            
            unsafe {
                if libc::setsockopt(fd, libc::SOL_SOCKET, SO_TIMESTAMPING, &flags as *const _ as *const libc::c_void, std::mem::size_of::<libc::c_int>() as libc::socklen_t) < 0 {
                    warn!("[BRIDGE] SO_TIMESTAMPING failed. Hardware PTP might be disabled.");
                } else {
                    info!("[BRIDGE] SO_TIMESTAMPING enabled (Hardware PTP active).");
                }
            }

            // 2. SO_TXTIME (Deterministic Egress)
            // config for etf qdisc: clockid = CLOCK_TAI
            #[repr(C)]
            struct SockTxtime {
                clockid: libc::clockid_t,
                flags: u32,
            }
            let sk_txtime = SockTxtime {
                clockid: libc::CLOCK_TAI,
                flags: 0,
            };
            
            unsafe {
                if libc::setsockopt(fd, libc::SOL_SOCKET, SO_TXTIME, &sk_txtime as *const _ as *const libc::c_void, std::mem::size_of::<SockTxtime>() as libc::socklen_t) < 0 {
                    warn!("[BRIDGE] SO_TXTIME failed. Defaulting to software scheduling.");
                } else {
                    info!("[BRIDGE] SO_TXTIME enabled (Egress Bridge Locked).");
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            // macOS low-latency hint
            // SO_NET_SERVICE_TYPE = 0x1102
            // NET_SERVICE_TYPE_VI = 3
            const SO_NET_SERVICE_TYPE: libc::c_int = 0x1102;
            const NET_SERVICE_TYPE_VI: libc::c_int = 3;
            
            unsafe {
                if libc::setsockopt(fd, libc::SOL_SOCKET, SO_NET_SERVICE_TYPE, &NET_SERVICE_TYPE_VI as *const _ as *const libc::c_void, std::mem::size_of::<libc::c_int>() as libc::socklen_t) < 0 {
                    warn!("[BRIDGE] SO_NET_SERVICE_TYPE failed.");
                } else {
                    info!("[BRIDGE] macOS Low-Latency Hint Active (VI Service Type).");
                }
            }
        }

        Ok(Self { socket })
    }

    pub fn send_at(&self, addr: SocketAddr, payload: &[u8], target_time_ns: u64) -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            use nix::sys::socket::{sendmsg, ControlMessage, MsgFlags, SockAddr};
            use std::io::IoSlice;

            let iov = [IoSlice::new(payload)];
            let cmsgs = [ControlMessage::TxTime(target_time_ns)];
            let nix_addr = SockAddr::from(addr);

            sendmsg(
                self.socket.as_raw_fd(),
                &iov,
                &cmsgs,
                MsgFlags::empty(),
                Some(&nix_addr)
            ).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Fallback for macOS/other: Regular send_to
            // Jitter is still minimized by the real-time metronome, but TXTIME gate is absent.
            self.socket.send_to(payload, addr)?;
            Ok(())
        }
    }
}
