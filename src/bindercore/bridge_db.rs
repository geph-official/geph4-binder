use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use geph4_binder_transport::BridgeDescriptor;
use itertools::Itertools;
use parking_lot::RwLock;

use super::PostgresPool;

type Sh<T> = Arc<RwLock<T>>;

type BridgeStore = HashMap<String, HashSet<(String, BridgeDescriptor)>>;

#[derive(Clone, Debug)]
/// A struct describing all the information in an uploaded bridge descriptor
pub struct FullBridgeInfo {
    pub sosistab_pubkey: x25519_dalek::PublicKey,
    pub bridge_address: SocketAddr,
    pub bridge_group: String,
    pub exit_hostname: String,
    pub update_time: u64,
    pub exit_signature: ed25519_dalek::Signature,
}

/// A structs that efficiently manages the available bridges and gives out bridges to people.
pub struct BridgeDb {
    db_pool: PostgresPool,
    // list of known bridge descriptors, sorted by exit.
    bridge_descs: Sh<BridgeStore>,
    // token blacklist
    token_blacklist: Sh<HashSet<String>>,
    // premium routes
    route_premium: Sh<HashSet<String>>,
}

impl BridgeDb {
    /// Creates a new BridgeDb, given a handle to the global postgres database.
    pub fn new(db_pool: PostgresPool) -> Self {
        let bridge_descs: Sh<BridgeStore> = Default::default();
        let token_blacklist: Sh<HashSet<String>> = Default::default();
        let route_premium: Sh<HashSet<String>> = Default::default();
        // spawn the bridge updater
        {
            let db_pool = db_pool.clone();
            let bridge_descs = bridge_descs.clone();
            let token_blacklist = token_blacklist.clone();
            let route_premium = route_premium.clone();
            std::thread::Builder::new()
                .name("bridge-sync".into())
                .spawn(|| bridge_updater(db_pool, bridge_descs, token_blacklist, route_premium))
                .unwrap();
        }
        Self {
            db_pool,
            bridge_descs,
            token_blacklist,
            route_premium,
        }
    }

    /// Obtains a bridge assignment for the given string.
    pub fn assign_bridges(
        &self,
        opaque_id: &str,
        exit_hostname: &str,
        is_premium: bool,
    ) -> Vec<BridgeDescriptor> {
        // if we are blacklisted, then we all get thrown into the same bin in order to not disrupt normal users.
        let opaque_id = if self.token_blacklist.read().contains(opaque_id) {
            "!!!BADGUY!!!"
        } else {
            opaque_id
        };

        // read all the bridges for this exit out right off the bat
        let by_group = self
            .bridge_descs
            .read()
            .get(exit_hostname)
            .map(|s| {
                s.iter().map(|p| (p.0.clone(), p.1.clone())).fold(
                    HashMap::new(),
                    |mut map: HashMap<String, Vec<BridgeDescriptor>>, (key, val)| {
                        map.entry(key).or_default().push(val);
                        map
                    },
                )
            })
            .unwrap_or_default();
        // for each group, pick out the "best" one, based on rendezvous hashing
        let mut res = by_group
            .into_iter()
            .filter_map(|(group, routes)| {
                if !is_premium && self.route_premium.read().contains(&group) {
                    return None;
                }
                routes.into_iter().max_by_key(|k| {
                    blake3::hash(format!("{}-{}", k.endpoint.ip(), opaque_id).as_bytes()).to_hex()
                })
            })
            .collect_vec();
        // TODO something better than this
        if opaque_id == "!!!BADGUY!!!" {
            // give out misinformation
            for desc in res.iter_mut() {
                let real_ip = desc.endpoint.ip();
                if let IpAddr::V4(v4) = real_ip {
                    let [a, b, c, _] = v4.octets();
                    let fake_v4 = Ipv4Addr::from([a, b, c, a ^ b ^ c]);
                    desc.endpoint.set_ip(fake_v4.into());
                }
            }
        }

        res
    }
}

/// Thread that updates bridges from the background periodically.
fn bridge_updater(
    db_pool: PostgresPool,
    bridge_descs: Sh<BridgeStore>,
    token_blacklist: Sh<HashSet<String>>,
    route_premium: Sh<HashSet<String>>,
) {
    let inner = || -> anyhow::Result<()> {
        let mut conn = db_pool.get()?;
        let mut txn = conn.transaction()?;
        let route_rows = txn.query(
            "select bridge_address,sosistab_pubkey,bridge_group,hostname from routes where bridge_group not like '%sosistab2%'",
            &[],
        )?;
        // form the entire hashmap anew
        let mut new_bridge_descs: BridgeStore = HashMap::new();
        for row in route_rows {
            let bridge_address: String = row.get(0);
            let bridge_address: SocketAddr = bridge_address.parse()?;
            let sosistab_key: Vec<u8> = row.get(1);
            let sosistab_key: [u8; 32] = sosistab_key.as_slice().try_into()?;
            let sosistab_key = x25519_dalek::PublicKey::from(sosistab_key);
            let group: String = row.get(2);
            let hostname: String = row.get(3);
            new_bridge_descs.entry(hostname).or_default().insert((
                group,
                BridgeDescriptor {
                    endpoint: bridge_address,
                    sosistab_key,
                },
            ));
        }
        // then we query for the token blacklist
        let mut new_token_blacklist = HashSet::new();
        let token_blacklist_rows = txn.query("select key from token_blacklist", &[])?;
        for row in token_blacklist_rows {
            let key: String = row.get(0);
            new_token_blacklist.insert(key);
        }
        let mut new_route_premium = HashSet::new();
        let route_premium_rows = txn.query("select bridge_group from route_premium", &[])?;
        for row in route_premium_rows {
            let key: String = row.get(0);
            new_route_premium.insert(key);
        }
        txn.execute(
            "delete from bridge_assignments_new where createtime < NOW() - interval '24 hour'",
            &[],
        )?;
        txn.execute(
            "delete from routes where update_time < NOW() - interval '3 minute'",
            &[],
        )?;
        txn.commit()?;
        // replace the hashmaps atomically
        *bridge_descs.write() = new_bridge_descs;
        *token_blacklist.write() = new_token_blacklist;
        *route_premium.write() = new_route_premium;
        Ok(())
    };
    loop {
        let start = Instant::now();
        if let Err(err) = inner() {
            log::warn!("bridge_db sync fail: {:?}", err);
        } else {
            log::info!("bridge db synced in {:?}", start.elapsed());
        }
        // random sleep duration to prevent patterns from forming
        if !bridge_descs.read().is_empty() {
            let next_pulse = UNIX_EPOCH
                + (Duration::from_secs(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                        / 60
                        * 60
                        + 60,
                ));
            let to_sleep = next_pulse
                .duration_since(SystemTime::now())
                .unwrap_or_else(|_| Duration::from_secs(1));
            log::info!("waiting {:?} until next bridge db sync", to_sleep);
            std::thread::sleep(to_sleep);
        } else {
            std::thread::sleep(Duration::from_secs(10));
        }
    }
}
