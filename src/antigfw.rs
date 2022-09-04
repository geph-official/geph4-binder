use std::net::{SocketAddr, UdpSocket};

use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
pub enum Report {
    /// Reports a bridge that's now blocked
    Blocked(String),
    /// Reports an IP/UID association
    IpUid { ip: String, uid: u64 },
    /// Reports an IP/key association
    IpKey { ip: String, key: String },
}

/// A client for GFW reporting
pub struct GfwReportClient {
    sock: UdpSocket,
    remote: SocketAddr,
}

impl GfwReportClient {
    /// Create a new GFW reporting client
    pub fn new(remote: SocketAddr) -> Self {
        let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
        Self { sock, remote }
    }

    /// Sends a report to the remote
    pub fn send(&self, r: Report) {
        let bts = serde_json::to_vec(&r).unwrap();
        if let Err(err) = self.sock.send_to(&bts, self.remote) {
            log::error!("failed to send report: {:?}", err);
        }
    }
}
