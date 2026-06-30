//! smoltcp `Device` adapter over virtio-net `NetRx` / raw Ethernet TX.

use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;

use crate::driver::NetRx;
use crate::virtio::{VirtioNet, VirtioNetHeader};

const ETH_MAX: usize = 1514;

static mut RX_ETH: [u8; ETH_MAX] = [0u8; ETH_MAX];
static mut RX_LEN: usize = 0;

/// Stage an Ethernet frame for the next `receive()` (lab / loopback tests).
pub unsafe fn stage_rx_frame(eth: &[u8]) {
    let len = eth.len().min(ETH_MAX);
    RX_ETH[..len].copy_from_slice(&eth[..len]);
    RX_LEN = len;
}

/// Virtio-backed smoltcp device (single-frame RX staging).
pub struct VirtioDevice<'a> {
    net: &'a VirtioNet,
    rx_ready: bool,
}

impl<'a> VirtioDevice<'a> {
    pub fn new(net: &'a VirtioNet) -> Self {
        Self {
            net,
            rx_ready: false,
        }
    }

    pub fn set_rx_ready(&mut self, ready: bool) {
        self.rx_ready = ready;
    }

    /// Pull one frame from virtio into the static RX staging buffer.
    pub fn poll_virtio(&mut self) {
        if self.rx_ready {
            return;
        }
        let _ = NetRx::poll_rx(self.net, |data, len| {
            let hdr = VirtioNetHeader::LEN;
            if len <= hdr {
                return;
            }
            let eth_len = (len - hdr).min(ETH_MAX);
            unsafe {
                RX_ETH[..eth_len].copy_from_slice(&data[hdr..hdr + eth_len]);
                RX_LEN = eth_len;
            }
            self.rx_ready = true;
        });
    }
}

pub struct VirtioRxToken {
    ready: bool,
}

impl phy::RxToken for VirtioRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        if self.ready {
            unsafe { f(&RX_ETH[..RX_LEN]) }
        } else {
            f(&[])
        }
    }
}

pub struct VirtioTxToken<'a> {
    net: &'a VirtioNet,
}

impl<'a> phy::TxToken for VirtioTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = [0u8; ETH_MAX];
        let len = len.min(ETH_MAX);
        let result = f(&mut buf[..len]);
        let _ = self.net.send_eth_frame(&buf[..len]);
        result
    }
}

impl<'a> Device for VirtioDevice<'a> {
    type RxToken<'b>
        = VirtioRxToken
    where
        Self: 'b;
    type TxToken<'b>
        = VirtioTxToken<'a>
    where
        Self: 'b;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if !self.rx_ready {
            return None;
        }
        self.rx_ready = false;
        Some((
            VirtioRxToken { ready: true },
            VirtioTxToken { net: self.net },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(VirtioTxToken { net: self.net })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = ETH_MAX;
        caps.max_burst_size = Some(ETH_MAX);
        caps.medium = Medium::Ethernet;
        caps
    }
}
