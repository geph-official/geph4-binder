use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use async_compat::CompatExt;
use async_trait::async_trait;
use backoff::{backoff::Backoff, ExponentialBackoffBuilder};
use bytes::Bytes;
use futures_lite::Future;

use geph4_protocol::binder::protocol::{
    box_decrypt, box_encrypt, AuthError, AuthRequest, AuthResponse, BinderProtocol, BinderService,
    BlindToken, BridgeDescriptor, Captcha, Level, MasterSummary, MiscFatalError, RegisterError,
    RpcError,
};
use melnet2::{wire::http::HttpBackhaul, Backhaul};
use nanorpc::{DynRpcTransport, JrpcRequest, JrpcResponse, RpcService, RpcTransport};
use once_cell::sync::Lazy;
use smol_str::SmolStr;
use warp::Filter;

use crate::{bindercore_v2::BinderCoreV2, Opt};

pub async fn start_server(core_v2: BinderCoreV2, opt: Opt) -> anyhow::Result<()> {
    let my_sk = core_v2.get_master_sk().await?;
    let statsd_client = Arc::new(statsd::Client::new(opt.statsd_addr, "geph4.binder").unwrap());
    log::info!("NEW HTTP listening on {}", opt.listen_new);
    let bcw = BinderCoreWrapper {
        core_v2: Arc::new(core_v2),
    };
    let bcw = Arc::new(BinderService(bcw.clone()));
    let statsd_client = statsd_client.clone();
    let serve = warp::post()
        .and(warp::body::content_length_limit(1024 * 512))
        .and(warp::body::bytes())
        .then(move |s: bytes::Bytes| {
            let my_sk = my_sk.clone();
            let bcw = bcw.clone();
            let statsd_client = statsd_client.clone();
            async move {
                let fallible = async {
                    let (decrypted, their_pk) = box_decrypt(&s, my_sk.clone())?;
                    let start = Instant::now();
                    let req: JrpcRequest = serde_json::from_slice(&decrypted)?;
                    statsd_client.incr(&req.method);
                    let method = req.method.clone();
                    let resp = bcw.respond_raw(req).await;
                    statsd_client.timer(
                        &format!("latencyv2.{}", method),
                        start.elapsed().as_secs_f64(),
                    );
                    if start.elapsed() > Duration::from_secs(1) {
                        log::debug!(
                            "** req {} of {} bts responded in {:.2}ms",
                            method,
                            s.len(),
                            start.elapsed().as_secs_f64() * 1000.0
                        );
                    }
                    let resp = serde_json::to_vec(&resp)?;
                    let resp = box_encrypt(&resp, my_sk, their_pk);
                    anyhow::Ok(resp)
                };
                if let Ok(res) = fallible.await {
                    res.to_vec()
                } else {
                    Bytes::new().to_vec()
                }
            }
        });

    warp::serve(serve).run(opt.listen_new).compat().await;
    Ok(())
}

#[derive(Clone)]
struct BinderCoreWrapper {
    core_v2: Arc<BinderCoreV2>,
}

#[async_trait]
impl BinderProtocol for BinderCoreWrapper {
    async fn authenticate(&self, auth_req: AuthRequest) -> Result<AuthResponse, AuthError> {
        backoff(|| self.core_v2.authenticate(&auth_req)).await
    }

    async fn validate(&self, token: BlindToken) -> bool {
        self.core_v2.validate(token.clone()).await
    }

    async fn get_captcha(&self) -> Result<Captcha, MiscFatalError> {
        Ok(backoff(|| self.core_v2.get_captcha()).await)
    }

    async fn register_user(
        &self,
        username: SmolStr,
        password: SmolStr,
        captcha_id: SmolStr,
        captcha_soln: SmolStr,
    ) -> Result<(), RegisterError> {
        backoff(|| {
            self.core_v2
                .create_user(&username, &password, &captcha_id, &captcha_soln)
        })
        .await
    }

    async fn delete_user(&self, username: SmolStr, password: SmolStr) -> Result<(), AuthError> {
        backoff(|| self.core_v2.delete_user(&username, &password)).await
    }

    async fn add_bridge_route(
        &self,
        descriptor: geph4_protocol::binder::protocol::BridgeDescriptor,
    ) -> Result<(), MiscFatalError> {
        self.core_v2
            .add_bridge_route(descriptor)
            .await
            .map_err(|e| {
                log::error!("FATAL error adding bridges: {:?}", e);
                MiscFatalError::Database(e.to_string().into())
            })
    }

    async fn get_summary(&self) -> MasterSummary {
        backoff(|| self.core_v2.get_summary()).await
    }

    async fn get_bridges(&self, token: BlindToken, exit: SmolStr) -> Vec<BridgeDescriptor> {
        backoff(|| self.core_v2.get_bridges(token.clone(), exit.clone(), true))
            .await
            .into_iter()
            .filter(|s| s.protocol == "sosistab")
            .collect()
    }

    async fn get_bridges_v2(&self, token: BlindToken, exit: SmolStr) -> Vec<BridgeDescriptor> {
        backoff(|| self.core_v2.get_bridges(token.clone(), exit.clone(), true))
            .await
            .into_iter()
            .filter(|s| s.protocol != "sosistab")
            .collect()
    }

    async fn get_mizaru_pk(&self, level: Level) -> mizaru::PublicKey {
        self.core_v2.get_mizaru_sk(level).await.to_public_key()
    }

    async fn get_mizaru_epoch_key(&self, level: Level, epoch: u16) -> rsa::RSAPublicKey {
        self.core_v2.get_epoch_key(level, epoch as usize).await
    }

    async fn get_announcements(&self) -> String {
        self.core_v2.get_announcements().await
    }

    /// Reverse proxies requests to melnode
    async fn reverse_proxy_melnode(&self, req: JrpcRequest) -> Result<JrpcResponse, RpcError> {
        // find a melnode and connect to it
        let bootstrap_routes = melbootstrap::bootstrap_routes(melstructs::NetID::Mainnet);
        let route = *bootstrap_routes
            .first()
            .context("Error retreiving bootstrap routes")
            .map_err(|_| RpcError::BootstrapFailed)?;
        static BACKHAUL: Lazy<HttpBackhaul> = Lazy::new(HttpBackhaul::new);
        let rpc_transport = DynRpcTransport::new(
            BACKHAUL
                .connect(route.to_string().into())
                .await
                .map_err(|_| RpcError::ConnectFailed)?,
        );

        // send!
        let resp = rpc_transport
            .call_raw(req)
            .await
            .map_err(|_| RpcError::CommFailed)?;
        Ok(resp)
    }
}

async fn backoff<T, Fut: Future<Output = anyhow::Result<T>>>(mut f: impl FnMut() -> Fut) -> T {
    let mut backoff = ExponentialBackoffBuilder::new()
        .with_max_elapsed_time(None)
        .build();
    loop {
        match f().await {
            Ok(res) => return res,
            Err(err) => {
                let interval = backoff.next_backoff().unwrap();
                log::warn!("retrying in {:?} due to {:?}", interval, err);
                smol::Timer::after(interval).await;
            }
        }
    }
}