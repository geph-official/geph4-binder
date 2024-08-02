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

pub struct BridgeStore {
    store: DashMap<BridgeId, BridgeInfo>,
    exit_index: DashMap<SmolStr, Vec<BridgeId>>,
}

impl Default for BridgeStore {
    fn default() -> Self {
        BridgeStore {
            store: DashMap::new(),
            exit_index: DashMap::new(),
        }
    }
}

impl BridgeStore {
    pub fn add_bridge(&self, bridge: &BridgeDescriptor) {
        let id = (bridge.protocol.clone(), bridge.endpoint);
        self.store
            .insert(id.clone(), (bridge.clone(), bridge.update_time));

        self.exit_index
            .entry(bridge.exit_hostname.clone())
            .or_default()
            .push(id);
    }

    pub fn get_bridges(&self, exit_hostname: SmolStr) -> Vec<BridgeDescriptor> {
        self.exit_index
            .get(&exit_hostname)
            .map(|bridge_ids| {
                bridge_ids
                    .iter()
                    .filter_map(|id| self.store.get(id).map(|bridge_info| bridge_info.0.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn delete_bridge(&self, bridge_id: &BridgeId) {
        if let Some((_, (bridge, _))) = self.store.remove(bridge_id) {
            if let Some(mut exit_bridges) = self.exit_index.get_mut(&bridge.exit_hostname) {
                exit_bridges.retain(|id| id != bridge_id);
            }
        }
    }

    pub fn delete_expired_bridges(&self, time_to_live_secs: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let expired: Vec<_> = self
            .store
            .iter()
            .filter(|pair| {
                let (_, (_, update_time)) = pair.pair();
                *update_time < now - time_to_live_secs
            })
            .map(|pair| pair.key().clone())
            .collect();

        for id in expired {
            self.delete_bridge(&id);
        }
    }
}
