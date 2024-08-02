use std::{
    num::NonZeroU32,
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc, LazyLock,
    },
    time::{Duration, Instant},
};

use anyhow::Context;
use async_compat::CompatExt;
use async_trait::async_trait;
use backoff::{backoff::Backoff, ExponentialBackoffBuilder};
use bytes::Bytes;
use futures_lite::Future;

use geph4_protocol::binder::protocol::{
    box_decrypt, box_encrypt, AuthError, AuthRequest, AuthRequestV2, AuthResponse, AuthResponseV2,
    BinderProtocol, BinderService, BlindToken, BridgeDescriptor, Captcha, Credentials, Level,
    MasterSummary, MiscFatalError, RegisterError, RpcError, UserInfoV2,
};
use governor::{
    clock::MonotonicClock,
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use melnet2::{wire::http::HttpBackhaul, Backhaul};
use moka::future::Cache;
use nanorpc::{DynRpcTransport, JrpcRequest, JrpcResponse, RpcService, RpcTransport};

use smol::lock::Semaphore;
use smol_str::SmolStr;
use smol_timeout::TimeoutExt;
use warp::Filter;

use crate::{
    bindercore_v2::{BinderCoreV2, POOL_SIZE},
    run_blocking, Opt,
};

const MAX_DATA_SIZE: usize = 2048;
const LOTTERY_THRESHOLD: u64 = 9223372036854775808; // this threshold excludes ~50% of hashes

const BASE_RPS: u32 = 10000;

static GOVERNOR: LazyLock<
    RateLimiter<NotKeyed, InMemoryState, MonotonicClock, NoOpMiddleware<Instant>>,
> = LazyLock::new(|| {
    RateLimiter::direct_with_clock(
        Quota::per_second(NonZeroU32::new(BASE_RPS).unwrap()),
        &MonotonicClock,
    )
});

static FAILED_REQUESTS: AtomicU64 = AtomicU64::new(0);

static TRUE_RPS: AtomicU32 = AtomicU32::new(500);

pub async fn start_server(core_v2: BinderCoreV2, opt: Opt) -> anyhow::Result<()> {
    smolscale::spawn(async {
        loop {
            let fail_count = FAILED_REQUESTS.swap(0, Ordering::Relaxed);
            let current_rps = TRUE_RPS.load(Ordering::Relaxed);
            let next_rps = if fail_count > 0 {
                (current_rps * 19 / 20).max(100)
            } else {
                (current_rps + 20).min(BASE_RPS)
            };
            TRUE_RPS.store(next_rps, Ordering::Relaxed);
            log::warn!("*** FAIL COUNT {fail_count}, current_rps {current_rps} ***");
            smol::Timer::after(Duration::from_secs(2)).await;
        }
    })
    .detach();

    let my_sk = core_v2.get_master_sk().await?;
    let statsd_client = Arc::new(statsd::Client::new(opt.statsd_addr, "geph4.binder").unwrap());
    log::info!("NEW HTTP listening on {}", opt.listen_new);
    let bcw = BinderCoreWrapper {
        core_v2: Arc::new(core_v2),
        melnode_cache: Cache::builder()
            .time_to_live(Duration::from_secs(5))
            .build()
            .into(),
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
                let chunk = BASE_RPS / TRUE_RPS.load(Ordering::Relaxed);
                if GOVERNOR
                    .check_n(NonZeroU32::new(chunk).unwrap())
                    .unwrap()
                    .is_err()
                {
                    // statsd_client.incr("GOVERNED");
                    // log::warn!("SLOWING DOWN");
                    return http::Response::builder()
                        .status(http::StatusCode::TOO_MANY_REQUESTS)
                        .body(Bytes::from_static(b"WAAY Too Many Requests"))
                        .unwrap();
                }

                let fallible = smolscale::spawn(async move {
                    let (decrypted, their_pk) = if let Ok(val) = run_blocking({
                        let my_sk = my_sk.clone();
                        move || box_decrypt(&s, my_sk.clone())
                    })
                    .await
                    {
                        val
                    } else {
                        return Ok(Bytes::new());
                    };
                    let start = Instant::now();
                    let req: JrpcRequest = serde_json::from_slice(&decrypted)?;
                    statsd_client.incr(&req.method);
                    let method = req.method.clone();
                    let resp = bcw.respond_raw(req).timeout(Duration::from_secs(3)).await;
                    if let Some(resp) = resp {
                        statsd_client.timer(
                            &format!("latencyv2.{}", method),
                            start.elapsed().as_secs_f64(),
                        );
                        let resp = serde_json::to_vec(&resp)?;
                        let resp = run_blocking(move || box_encrypt(&resp, my_sk, their_pk)).await;
                        anyhow::Ok(resp)
                    } else {
                        anyhow::bail!("timeout due to overload")
                    }
                });
                match fallible.await {
                    Ok(res) => http::Response::builder().body(res).unwrap(),
                    Err(e) => {
                        log::error!("error handling request: {:?}", e);
                        FAILED_REQUESTS.fetch_add(1, Ordering::Relaxed);
                        http::Response::builder()
                            .status(http::StatusCode::INTERNAL_SERVER_ERROR)
                            .body(Bytes::copy_from_slice(
                                format!("internal server error: {:?}", e).as_bytes(),
                            ))
                            .unwrap()
                    }
                }
            }
        });

    warp::serve(serve).run(opt.listen_new).compat().await;
    Ok(())
}

#[derive(Clone)]
struct BinderCoreWrapper {
    core_v2: Arc<BinderCoreV2>,
    melnode_cache: Arc<Cache<Vec<u8>, JrpcResponse>>,
}

#[async_trait]
impl BinderProtocol for BinderCoreWrapper {
    async fn authenticate(&self, auth_req: AuthRequest) -> Result<AuthResponse, AuthError> {
        backoff(|| self.core_v2.authenticate(&auth_req)).await
    }

    async fn authenticate_v2(&self, auth_req: AuthRequestV2) -> Result<AuthResponseV2, AuthError> {
        backoff(|| self.core_v2.authenticate_v2(&auth_req)).await
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

    /// Registers a new user.
    async fn register_user_v2(
        &self,
        credentials: Credentials,
        captcha_id: SmolStr,
        captcha_soln: SmolStr,
    ) -> Result<(), RegisterError> {
        backoff(|| {
            self.core_v2
                .create_user_v2(credentials.clone(), &captcha_id, &captcha_soln)
        })
        .await
    }

    async fn delete_user(&self, username: SmolStr, password: SmolStr) -> Result<(), AuthError> {
        backoff(|| self.core_v2.delete_user(&username, &password)).await
    }

    async fn delete_user_v2(&self, credentials: Credentials) -> Result<(), AuthError> {
        backoff(|| self.core_v2.delete_user_v2(credentials.clone())).await
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
    async fn reverse_proxy_melnode(&self, _req: JrpcRequest) -> Result<JrpcResponse, RpcError> {
        Err(RpcError::CommFailed)
    }

    async fn get_login_url(&self, credentials: Credentials) -> Result<String, AuthError> {
        self.core_v2.get_login_url(credentials).await
    }

    async fn add_metric(
        &self,
        session: i64,
        data: serde_json::Value,
    ) -> Result<(), MiscFatalError> {
        let data_str = serde_json::to_string(&data).map_err(|e| {
            log::error!("error serializing metric data: {:?}", e);
            MiscFatalError::Database(e.to_string().into())
        })?;

        if data_str.as_bytes().len() > MAX_DATA_SIZE {
            let e = format!("metric data exceeds {MAX_DATA_SIZE} byte limit");
            log::error!("{}", e);
            return Err(MiscFatalError::Database(e.into()));
        }

        let session_bytes = bincode::serialize(&session).map_err(|e| {
            log::error!("error serializing metric session: {:?}", e);
            MiscFatalError::Database(e.to_string().into())
        })?;
        let data_hash = blake3::hash(&session_bytes);
        let hash_value: u64 = u64::from_be_bytes(data_hash.as_bytes()[0..8].try_into().unwrap());

        if hash_value <= LOTTERY_THRESHOLD {
            return Ok(());
        }

        self.core_v2.add_metric(session, data).await.map_err(|e| {
            log::error!("error adding metric: {:?}", e);
            MiscFatalError::Database(e.to_string().into())
        })?;

        Ok(())
    }

    async fn get_user_info(&self, credentials: Credentials) -> Result<UserInfoV2, AuthError> {
        backoff(|| {
            let credentials = credentials.clone();
            async move {
                if !self.core_v2.verify(credentials.clone()).await? {
                    return Ok(Err(AuthError::InvalidCredentials));
                }
                let user_info = self.core_v2.get_user_info_v2(credentials).await?;
                if let Some(user_info) = user_info {
                    Ok(Ok(user_info))
                } else {
                    Ok(Err(AuthError::InvalidCredentials))
                }
            }
        })
        .await
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
