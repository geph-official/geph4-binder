mod antigfw;
mod bindercore;
mod responder;
use async_trait::async_trait;
use bindercore::BinderCore;
use bytes::Bytes;
use env_logger::Env;
use geph4_binder_transport::BinderError;
use geph4_protocol::binder::protocol::{
    box_decrypt, box_encrypt, AuthError, AuthRequest, AuthResponse, BinderProtocol, BinderService,
    BlindToken, BridgeDescriptor, Captcha, ExitDescriptor, Level, MasterSummary, MiscFatalError,
    RegisterError, SubscriptionInfo, UserInfo,
};
use nanorpc::RpcService;
use once_cell::sync::Lazy;
use rusty_pool::ThreadPool;
use smol_str::SmolStr;
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use structopt::StructOpt;
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

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("geph4_binder=info")).init();
    let opt = Opt::from_args();
    let binder_core = bindercore::BinderCore::create(
        &opt.database,
        &opt.captcha_endpoint,
        &std::fs::read(opt.database_ca_cert).unwrap(),
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
    let statsd_client = statsd::Client::new(opt.statsd_addr, "geph4.binder").unwrap();
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
        std::thread::spawn(move || {
            log::info!("NEW HTTP listening on {}", opt.listen_new);
            handle_requests_new(tiny_http::Server::http(opt.listen_new).unwrap(), bcore)
        });
    }
    responder::handle_requests(http_serv, bcore, Arc::new(statsd_client))
}

fn handle_requests_new(server: tiny_http::Server, bcore: Arc<BinderCore>) {
    let sk = bcore.get_master_sk().unwrap();
    let bcw = BinderCoreWrapper(bcore);
    for mut request in server.incoming_requests() {
        let bcw = BinderService(bcw.clone());
        let my_sk = sk.clone();
        smolscale::spawn(async move {
            let mut s = Vec::new();
            request.as_reader().read_to_end(&mut s)?;
            log::debug!("** new msg of {} bts", s.len());
            let (decrypted, their_pk) = box_decrypt(&s, my_sk.clone())?;
            log::debug!("** new msg of {} bts decrypted", s.len());
            let resp = bcw.respond_raw(serde_json::from_slice(&decrypted)?).await;
            let resp = serde_json::to_vec(&resp)?;
            let resp = box_encrypt(&resp, my_sk, their_pk);
            let _ = request.respond(tiny_http::Response::from_data(resp));
            anyhow::Ok(())
        })
        .detach()
    }
}

#[derive(Clone)]
struct BinderCoreWrapper(Arc<BinderCore>);

#[async_trait]
impl BinderProtocol for BinderCoreWrapper {
    async fn authenticate(&self, auth_req: AuthRequest) -> Result<AuthResponse, AuthError> {
        let this = self.0.clone();
        run_blocking(move || {
            let (user_info, blind_signature) = this
                .authenticate(
                    "0.0.0.0".parse().unwrap(),
                    &auth_req.username,
                    &auth_req.password,
                    lvl_to_str(auth_req.level),
                    auth_req.epoch as usize,
                    &auth_req.blinded_digest,
                )
                .map_err(to_autherr)?;
            Ok(AuthResponse {
                user_info: UserInfo {
                    userid: user_info.userid,
                    username: user_info.username.into(),
                    subscription: user_info.subscription.map(|sub| SubscriptionInfo {
                        level: str_to_level(&sub.level),
                        expires_unix: sub.expires_unix,
                    }),
                },
                blind_signature_bincode: bincode::serialize(&blind_signature).unwrap().into(),
            })
        })
        .await
    }

    async fn validate(&self, token: BlindToken) -> bool {
        loop {
            let this = self.0.clone();
            let token = token.clone();
            let res = run_blocking(move || {
                let res = if let Ok(v) = bincode::deserialize(&token.unblinded_signature_bincode) {
                    v
                } else {
                    return Ok(false);
                };
                this.validate(lvl_to_str(token.level), &token.unblinded_digest, &res)
            })
            .await;
            match res {
                Err(e) => log::warn!("{:?}", e),
                Ok(b) => return b,
            }
        }
    }

    async fn get_captcha(&self) -> Result<Captcha, MiscFatalError> {
        let this = self.0.clone();
        run_blocking(move || {
            let (s, v) = this
                .get_captcha()
                .map_err(|e| MiscFatalError::BadNet(format!("{:?}", e).into()))?;
            Ok(Captcha {
                captcha_id: s.into(),
                png_data: v.into(),
            })
        })
        .await
    }

    async fn register_user(
        &self,
        username: SmolStr,
        password: SmolStr,
        captcha_id: SmolStr,
        captcha_soln: SmolStr,
    ) -> Result<(), RegisterError> {
        let this = self.0.clone();
        run_blocking(move || {
            this.create_user(&username, &password, &captcha_id, &captcha_soln)
                .map_err(|e| match e {
                    geph4_binder_transport::BinderError::UserAlreadyExists => {
                        RegisterError::DuplicateUsername
                    }
                    e => RegisterError::Other(format!("{:?}", e).into()),
                })
        })
        .await
    }

    async fn delete_user(&self, username: SmolStr, password: SmolStr) -> Result<(), AuthError> {
        let this = self.0.clone();
        run_blocking(move || this.delete_user(&username, &password).map_err(to_autherr)).await
    }

    async fn add_bridge_route(&self, descriptor: BridgeDescriptor) -> Result<(), MiscFatalError> {
        let this = self.0.clone();
        run_blocking(move || {
            this.add_bridge_route(
                descriptor.sosistab_key,
                descriptor.endpoint,
                &descriptor.alloc_group,
                &descriptor.exit_hostname,
                descriptor.update_time,
                ed25519_dalek::Signature::from_bytes(&descriptor.exit_signature)
                    .map_err(|e| MiscFatalError::Database(format!("{:?}", e).into()))?,
            )
            .map_err(|e| MiscFatalError::Database(format!("{:?}", e).into()))
        })
        .await
    }

    async fn get_summary(&self) -> MasterSummary {
        let this = self.0.clone();
        run_blocking(move || loop {
            let fallible_part = || {
                let all_exits = this.get_exits(false)?;
                let free_exits = this.get_exits(true)?;
                let mut vv = vec![];
                for legacy_exit in all_exits {
                    let allowed_levels = if free_exits
                        .iter()
                        .any(|s| s.hostname == legacy_exit.hostname)
                    {
                        vec![Level::Free, Level::Plus]
                    } else {
                        vec![Level::Plus]
                    };
                    let new = ExitDescriptor {
                        hostname: legacy_exit.hostname.into(),
                        signing_key: legacy_exit.signing_key,
                        country_code: legacy_exit.country_code.into(),
                        city_code: legacy_exit.city_code.into(),
                        direct_routes: vec![],
                        legacy_direct_sosistab_pk: legacy_exit.sosistab_key,
                        allowed_levels,
                    };
                    vv.push(new);
                }
                Ok::<_, BinderError>(vv)
            };
            match fallible_part() {
                Ok(val) => {
                    return MasterSummary {
                        exits: val,
                        bad_countries: vec!["cn".into(), "ir".into()],
                    }
                }
                Err(err) => {
                    log::warn!("retrying due to {:?}", err);
                    std::thread::sleep(Duration::from_millis(fastrand::u64(0..50)));
                }
            }
        })
        .await
    }

    async fn get_bridges(&self, token: BlindToken, exit: SmolStr) -> Vec<BridgeDescriptor> {
        let this = self.0.clone();
        run_blocking(move || {
            if let Ok(bridges) = this.get_bridges(
                "0.0.0.0".parse().unwrap(),
                lvl_to_str(token.level),
                &token.unblinded_digest,
                &if let Ok(v) = bincode::deserialize(&token.unblinded_signature_bincode) {
                    v
                } else {
                    return vec![];
                },
                &exit,
            ) {
                bridges
                    .into_iter()
                    .map(|legacy| BridgeDescriptor {
                        is_direct: false,
                        protocol: "sosistab".into(),
                        endpoint: legacy.endpoint,
                        sosistab_key: legacy.sosistab_key,
                        exit_hostname: exit.clone(),
                        alloc_group: "unknown".into(),
                        update_time: 0,
                        exit_signature: Bytes::copy_from_slice(b"fake"),
                    })
                    .collect()
            } else {
                vec![]
            }
        })
        .await
    }

    async fn get_mizaru_pk(&self, level: Level) -> mizaru::PublicKey {
        let this = self.0.clone();
        run_blocking(move || {
            this.get_mizaru_sk(lvl_to_str(level))
                .unwrap()
                .to_public_key()
        })
        .await
    }

    async fn get_mizaru_epoch_key(&self, level: Level, epoch: u16) -> rsa::RSAPublicKey {
        let this = self.0.clone();
        run_blocking(move || this.get_epoch_key(lvl_to_str(level), epoch as _).unwrap()).await
    }
}

fn lvl_to_str(l: Level) -> &'static str {
    match l {
        Level::Free => "free",
        Level::Plus => "plus",
    }
}

fn str_to_level(s: &str) -> Level {
    match s {
        "free" => Level::Free,
        _ => Level::Plus,
    }
}

fn to_autherr(e: BinderError) -> AuthError {
    match e {
        geph4_binder_transport::BinderError::WrongPassword
        | geph4_binder_transport::BinderError::NoUserFound => AuthError::InvalidUsernameOrPassword,
        geph4_binder_transport::BinderError::WrongLevel => AuthError::WrongLevel,
        e => AuthError::Other(format!("{:?}", e).into()),
    }
}

async fn run_blocking<T: Send + Sync + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    static POOL: Lazy<ThreadPool> =
        Lazy::new(|| ThreadPool::new(1, POOL_SIZE, Duration::from_secs(10)));
    let (mut send, recv) = async_oneshot::oneshot();
    POOL.execute(move || {
        let t = f();
        let _ = send.send(t);
    });
    recv.await.unwrap()
}
