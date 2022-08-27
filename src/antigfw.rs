use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr, UdpSocket},
    time::SystemTime,
};

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

/// A key representing an observed "users".
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum UserKey {
    UserID(i32),
    TokenHash(String),
}

/// An in-memory structure representing anti-GFW countermeasures.
#[derive(Default)]
pub struct Tracker {
    /// list of distinct IP addresses that have presented this key, along with their expiration dates.
    distinct_ip: BTreeMap<UserKey, BTreeSet<IpAddr>>,

    /// list of bad IP addresses, with their creation dates
    creation: BTreeMap<IpAddr, SystemTime>,

    /// reverse mapping of IP addresses to the userkeys that it mapped to.
    reverse: BTreeMap<IpAddr, BTreeSet<UserKey>>,
}

const BAN_THRESHOLD: usize = 30;

impl Tracker {
    /// Insert a key/IP pair
    pub fn insert(&mut self, key: UserKey, ip: IpAddr) {
        let mapping = self.distinct_ip.entry(key.clone()).or_default();
        mapping.insert(ip);
        self.creation.insert(ip, SystemTime::now());
        self.reverse.entry(ip).or_default().insert(key);
    }

    /// Look up a key, returning whether or not to ban.
    pub fn is_banned_key(&self, key: UserKey) -> bool {
        let map = self.distinct_ip.get(&key);
        if let Some(map) = map {
            let mut count = 0;
            for ip in map.iter() {
                if self.alive(*ip) {
                    count += 1;
                }
            }
            if count >= BAN_THRESHOLD {
                // log::warn!("banning {:?} with {} distinct IPs", key, count);
                return true;
            }
        }
        false
    }

    /// Looks up an IP, returning whether or not to ban.
    pub fn is_banned_ip(&self, ip: IpAddr) -> bool {
        let keys = self.lookup_ip(ip);
        for key in keys {
            if self.is_banned_key(key) {
                return true;
            }
        }
        false
    }

    /// Look up an IP address, returning the list of userkeys mapped to it.
    pub fn lookup_ip(&self, ip: IpAddr) -> BTreeSet<UserKey> {
        if self.alive(ip) {
            self.reverse.get(&ip).cloned().unwrap_or_default()
        } else {
            BTreeSet::new()
        }
    }

    fn alive(&self, ip: IpAddr) -> bool {
        self.creation
            .get(&ip)
            .map(|v| {
                v.elapsed()
                    .map(|v| v.as_secs() < 86400 * 7)
                    .unwrap_or_default()
            })
            .unwrap_or_default()
    }
}
