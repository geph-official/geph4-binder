mod bindercore;
mod bindercore_v2;
mod responder;
use async_compat::CompatExt;
use async_trait::async_trait;
use backoff::{backoff::Backoff, ExponentialBackoffBuilder};

use bindercore_v2::BinderCoreV2;
use bytes::Bytes;
use env_logger::Env;
use futures_lite::Future;

use geph4_protocol::binder::protocol::{
    box_decrypt, box_encrypt, AuthError, AuthRequest, AuthResponse, BinderProtocol, BinderService,
    BlindToken, BridgeDescriptor, Captcha, Level, MasterSummary, MiscFatalError, RegisterError,
};
use nanorpc::{JrpcRequest, RpcService};

use smol_str::SmolStr;
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Instant};
use structopt::StructOpt;
use warp::Filter;
const POOL_SIZE: usize = 16;

#[derive(Debug, StructOpt)]
struct Opt {
    /// PostgreSQL database URL
    #[structopt(long)]
    database: String,
    /// Path to database connection CA file
    #[structopt(long)]
    database_ca_cert: PathBuf,
    /// Captcha service
    #[structopt(default_value = "https://single-verve-156821.ew.r.appspot.com", long)]
    captcha_endpoint: String,
    /// Legacy HTTP listening port
    #[structopt(default_value = "127.0.0.1:18080", long)]
    listen_http: SocketAddr,
    /// New HTTP listening port
    #[structopt(default_value = "0.0.0.0:28080", long)]
    listen_new: SocketAddr,
    /// GFW reporting address
    #[structopt(long)]
    gfwreport_addr: SocketAddr,
    #[structopt(long, default_value = "172.105.28.221:8125")]
    /// UDP address of the statsd daemon
    statsd_addr: SocketAddr,
}

fn main() -> anyhow::Result<()> {
    smolscale::block_on(async {
        env_logger::Builder::from_env(Env::default().default_filter_or("geph4_binder=info")).init();
        let opt = Opt::from_args();

        let binder_core = bindercore::BinderCore::create(
            &opt.database,
            &opt.captcha_endpoint,
            &std::fs::read(&opt.database_ca_cert).unwrap(),
            opt.gfwreport_addr,
        );
        let master_secret = binder_core.get_master_sk().unwrap();
        let free_mizaru_sk = binder_core.get_mizaru_sk("free").unwrap();
        let plus_mizaru_sk = binder_core.get_mizaru_sk("plus").unwrap();
        log::info!("geph4-binder starting with:");
        log::info!(
            "  Master x25519 public key = {}",
            hex::encode(x25519_dalek::PublicKey::from(&master_secret).to_bytes())
        );
        log::info!(
            "  Mizaru public key (FREE) = {}",
            hex::encode(free_mizaru_sk.to_public_key().0)
        );
        log::info!(
            "  Mizaru public key (PLUS) = {}",
            hex::encode(plus_mizaru_sk.to_public_key().0)
        );
        let statsd_client = Arc::new(statsd::Client::new(opt.statsd_addr, "geph4.binder").unwrap());
        let core_v2 = bindercore_v2::BinderCoreV2::connect(
            &opt.database,
            &opt.captcha_endpoint,
            &std::fs::read(&opt.database_ca_cert)?,
            statsd_client.clone(),
        )
        .await?;

        log::info!("core v2 initialized");
        // create server
        let copp = statsd::Client::new(opt.statsd_addr, "geph4.binder").unwrap();
        let http_serv =
            geph4_binder_transport::HttpServer::new(opt.listen_http, master_secret, move |time| {
                copp.timer("latency", time.as_secs_f64())
            });
        log::info!("LEGACY HTTP listening on {}", opt.listen_http);
        let bcore = Arc::new(binder_core);
        {
            let bcore = bcore.clone();
            let bcw = BinderCoreWrapper {
                core_v2: Arc::new(core_v2),
            };
            let statsd_client = statsd_client.clone();
            std::thread::spawn(move || {
                log::info!("NEW HTTP listening on {}", opt.listen_new);
                let my_sk = bcore.get_master_sk().unwrap();
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
                                log::debug!("** new msg {} of {} bts", req.method, s.len());
                                statsd_client.incr(&req.method);
                                let method = req.method.clone();
                                let resp = bcw.respond_raw(req).await;
                                statsd_client.timer(
                                    &format!("latencyv2.{}", method),
                                    start.elapsed().as_secs_f64(),
                                );
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

                smol::future::block_on(warp::serve(serve).run(opt.listen_new).compat())
            });
        }

        responder::handle_requests(http_serv, bcore, statsd_client);
        Ok(())
    })
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

    async fn add_bridge_route(&self, descriptor: BridgeDescriptor) -> Result<(), MiscFatalError> {
        self.core_v2
            .add_bridge_route(descriptor)
            .await
            .map_err(|e| MiscFatalError::Database(e.to_string().into()))
    }

    async fn get_summary(&self) -> MasterSummary {
        backoff(|| self.core_v2.get_summary()).await
    }

    async fn get_bridges(&self, token: BlindToken, exit: SmolStr) -> Vec<BridgeDescriptor> {
        backoff(|| self.core_v2.get_bridges(token.clone(), exit.clone())).await
    }

    async fn get_mizaru_pk(&self, level: Level) -> mizaru::PublicKey {
        self.core_v2.get_mizaru_sk(level).await.to_public_key()
    }

    async fn get_mizaru_epoch_key(&self, level: Level, epoch: u16) -> rsa::RSAPublicKey {
        self.core_v2.get_epoch_key(level, epoch as usize).await
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
