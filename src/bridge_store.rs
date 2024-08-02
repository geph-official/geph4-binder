use std::{
    collections::HashMap,
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use geph4_protocol::binder::protocol::BridgeDescriptor;
use parking_lot::RwLock;
use smol_str::SmolStr;

type UpdateTimestamp = u64;
type BridgeId = (SmolStr, SocketAddr);
type BridgeInfo = (BridgeDescriptor, UpdateTimestamp);

#[derive(Default)]
pub struct BridgeStore {
    inner: RwLock<Inner>,
}

#[derive(Default)]
struct Inner {
    store: HashMap<BridgeId, BridgeInfo>,
    exit_index: HashMap<SmolStr, Vec<BridgeId>>,
}

impl BridgeStore {
    pub fn add_bridge(&self, bridge: &BridgeDescriptor) {
        let id = (bridge.protocol.clone(), bridge.endpoint);
        let mut inner = self.inner.write();
        inner
            .store
            .insert(id.clone(), (bridge.clone(), bridge.update_time));
        inner
            .exit_index
            .entry(bridge.exit_hostname.clone())
            .or_default()
            .push(id);
    }

    pub fn get_bridges(&self, exit: &str) -> Vec<BridgeDescriptor> {
        let exit = SmolStr::new(exit);
        let inner = self.inner.read();
        if let Some(ids) = inner.exit_index.get(&exit) {
            ids.iter()
                .filter_map(|id| inner.store.get(id).map(|bridge_info| bridge_info.0.clone()))
                .collect()
        } else {
            Vec::new()
        }
    }

    pub fn delete_bridge(&self, bridge_id: &BridgeId) {
        let mut inner = self.inner.write();
        if let Some((bridge, _)) = inner.store.remove(bridge_id) {
            if let Some(ids) = inner.exit_index.get_mut(&bridge.exit_hostname) {
                ids.retain(|id| id != bridge_id);
                if ids.is_empty() {
                    inner.exit_index.remove(&bridge.exit_hostname);
                }
            }
        }
    }

    pub fn delete_expired_bridges(&self, time_to_live_secs: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let inner = self.inner.read();
        let expired_ids: Vec<BridgeId> = inner
            .store
            .iter()
            .filter_map(|(id, (_, update_time))| {
                if *update_time < now - time_to_live_secs {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();

        drop(inner);

        for id in expired_ids {
            self.delete_bridge(&id);
        }
    }
}
