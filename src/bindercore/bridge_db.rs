use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use geph4_binder_transport::BridgeDescriptor;
use itertools::Itertools;
use parking_lot::RwLock;
use rand::Rng;

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
}

impl BridgeDb {
    /// Creates a new BridgeDb, given a handle to the global postgres database.
    pub fn new(db_pool: PostgresPool) -> Self {
        let bridge_descs: Sh<BridgeStore> = Default::default();
        let token_blacklist: Sh<HashSet<String>> = Default::default();
        // spawn the bridge updater
        {
            let db_pool = db_pool.clone();
            let bridge_descs = bridge_descs.clone();
            let token_blacklist = token_blacklist.clone();
            std::thread::Builder::new()
                .name("bridge-sync".into())
                .spawn(|| bridge_updater(db_pool, bridge_descs, token_blacklist))
                .unwrap();
        }
        Self {
            db_pool,
            bridge_descs,
            token_blacklist,
        }
    }

    /// Obtains a bridge assignment for the given string.
    pub fn assign_bridges(&self, opaque_id: &str, exit_hostname: &str) -> Vec<BridgeDescriptor> {
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
        by_group
            .into_iter()
            .filter_map(|(group, routes)| {
                routes.into_iter().max_by_key(|k| {
                    blake3::hash(format!("{}-{}", k.endpoint, opaque_id).as_bytes()).to_hex()
                })
            })
            .collect_vec()
    }
}

/// Thread that updates bridges from the background periodically.
fn bridge_updater(
    db_pool: PostgresPool,
    bridge_descs: Sh<BridgeStore>,
    token_blacklist: Sh<HashSet<String>>,
) {
    let inner = || -> anyhow::Result<()> {
        let mut conn = db_pool.get()?;
        let mut txn = conn.transaction()?;
        let route_rows = txn.query("select bridge_address,sosistab_pubkey,bridge_group,hostname from routes where update_time > NOW() - interval '3 minute'", &[])?;
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
        txn.commit()?;
        // replace the hashmaps atomically
        *bridge_descs.write() = new_bridge_descs;
        *token_blacklist.write() = new_token_blacklist;
        Ok(())
    };
    loop {
        if let Err(err) = inner() {
            log::warn!("bridge_db sync fail: {:?}", err);
        }
        // random sleep duration to prevent patterns from forming
        std::thread::sleep(Duration::from_secs(rand::thread_rng().gen_range(60, 300)));
    }
}
