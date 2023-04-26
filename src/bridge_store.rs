use std::net::SocketAddr;

use dashmap::DashMap;
use geph4_protocol::binder::protocol::BridgeDescriptor;
use smol_str::SmolStr;

type UpdateTimestamp = u64;
type BridgeId = (SmolStr, SocketAddr);

#[derive(Debug)]
pub struct BridgeStore {
    store: DashMap<BridgeId, (BridgeDescriptor, UpdateTimestamp)>,
}

impl BridgeStore {
    pub fn add_bridge(&self, bridge: BridgeDescriptor) {
        let id = (bridge.protocol, bridge.endpoint);
        self.store.insert(id, (bridge, bridge.update_time));
    }

    pub fn get_bridges(&self) -> Vec<BridgeDescriptor> {
        self.store.iter().map(|entry| entry.0).collect()
    }
}
