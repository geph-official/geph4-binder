use std::{
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use dashmap::DashMap;
use geph4_protocol::binder::protocol::BridgeDescriptor;
use smol_str::SmolStr;

type UpdateTimestamp = u64;
type BridgeId = (SmolStr, SocketAddr);
type BridgeInfo = (BridgeDescriptor, UpdateTimestamp);

#[derive(Default)]
pub struct BridgeStore {
    store: DashMap<BridgeId, BridgeInfo>,
}

impl BridgeStore {
    pub fn add_bridge(&self, bridge: &BridgeDescriptor) {
        let id = (bridge.protocol.clone(), bridge.endpoint);
        self.store.insert(id, (bridge.clone(), bridge.update_time));
    }

    pub fn get_bridges(&self, exit_hostname: SmolStr) -> Vec<BridgeDescriptor> {
        self.store
            .clone()
            .into_iter()
            .map(|pair| {
                let bridge_info = pair.1;
                bridge_info.0
            })
            .filter(|bridge| bridge.exit_hostname == exit_hostname)
            .collect()
    }

    pub fn delete_bridge(&self, bridge_id: &BridgeId) {
        self.store.remove(bridge_id);
    }

    pub fn delete_expired_bridges(&self, time_to_live_secs: u64) {
        self.store
            .clone()
            .into_iter()
            .filter(|pair| {
                let bridge_info = pair.1.clone();
                let update_time = bridge_info.1;
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                // bridges expire after the given TTL
                update_time < now - time_to_live_secs
            })
            .for_each(|pair| {
                let id = pair.0;
                self.delete_bridge(&id);
            })
    }
}
