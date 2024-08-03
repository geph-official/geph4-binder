use std::{
    collections::HashMap,
    ffi::{CStr, CString},
    path::PathBuf,
    str::FromStr,
    sync::{Arc, LazyLock},
    thread::available_parallelism,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use async_compat::CompatExt;
use bytes::Bytes;
use chrono::Utc;
use dashmap::{lock::RwLock, DashMap};
use futures_util::{future::Shared, FutureExt};

use geph4_protocol::{
    binder::protocol::{
        verify_pk_auth, AuthError, AuthRequest, AuthRequestV2, AuthResponse, AuthResponseV2,
        BlindToken, BridgeDescriptor, Captcha, Credentials, ExitDescriptor, Level, MasterSummary,
        RegisterError, SubscriptionInfo, UserInfo, UserInfoV2,
    },
    bridge_exit::{BridgeExitClient, BridgeExitTransport},
};
use itertools::Itertools;

use moka::future::Cache;

use rand::{distributions::Alphanumeric, Rng};
use reqwest::StatusCode;
use semver::{Version, VersionReq};
use smol::Task;
use smol_str::SmolStr;
use smol_timeout::TimeoutExt;
use sosistab2::ObfsUdpPublic;
use sqlx::{
    pool::PoolOptions,
    postgres::{PgConnectOptions, PgSslMode},
    PgPool, Row,
};
use tap::Tap;

use crate::{bridge_store::BridgeStore, records::ExitRecord, run_blocking};

pub struct BinderCoreV2 {
    captcha_service_url: SmolStr,

    mizaru_sk: DashMap<Level, Shared<Task<mizaru::SecretKey>>>,

    // caches the network summary
    summary_cache: Arc<RwLock<Option<MasterSummary>>>,

    // caches the user info
    user_id_cache: Cache<Credentials, i32>,

    // caches the per-epoch key
    epoch_key_cache: Cache<(Level, usize), rsa::RSAPublicKey>,

    // caches bridges *per key*
    bridge_per_key: Cache<blake3::Hash, Vec<BridgeDescriptor>>,

    // in-memory store for bridge descriptors
    bridge_store: Arc<BridgeStore>,

    // pwd_cache: Cache<(SmolStr, SmolStr), bool>,

    // caches the "premium routes"
    premium_route_cache: Cache<(), imbl::HashSet<SmolStr>>,

    announcements_cache: Cache<(), String>,

    validate_cache: Cache<blake3::Hash, bool>,

    // cached list of subscriptions
    cached_subscriptions: Arc<RwLock<HashMap<i32, SubscriptionInfo>>>,

    // Postgres
    postgres: PgPool,

    // stats client
    statsd_client: Arc<statsd::Client>,

    _task: Task<()>,
}

pub static POOL_SIZE: LazyLock<u32> =
    LazyLock::new(|| 10 * available_parallelism().unwrap().get() as u32);

impl BinderCoreV2 {
    /// Constructs a BinderCore.
    pub async fn connect(
        database_url: &str,
        captcha_service_url: &str,
        cert: &[u8],
        statsd_client: Arc<statsd::Client>,
    ) -> anyhow::Result<Self> {
        let postgres = PoolOptions::new()
            .max_connections(*POOL_SIZE)
            .acquire_timeout(Duration::from_secs(10))
            .max_lifetime(Duration::from_secs(600))
            .connect_with(
                PgConnectOptions::from_str(database_url)?
                    .ssl_mode(PgSslMode::VerifyFull)
                    .ssl_root_cert_from_pem(cert.to_vec()),
            )
            .await?;

        let bridge_store = Arc::new(BridgeStore::default());
        let cached_subscriptions = Arc::new(RwLock::new(HashMap::new()));
        let summary_cache = Arc::new(RwLock::new(None));

        let _task = {
            let postgres = postgres.clone();
            let statsd_client = statsd_client.clone();
            let bridge_store = bridge_store.clone();
            let cached_subscriptions = cached_subscriptions.clone();
            let summary_cache = summary_cache.clone();
            smolscale::spawn(async move {
                let postgres2 = postgres.clone();
                let postgres3 = postgres.clone();
                let _refresh_cached_subs = smolscale::spawn(async move {
                    loop {
                        let rows: Result<Vec<(i32, String, f64)>, _> = sqlx::query_as(
                            "select id,plan,extract(epoch from expires) from subscriptions",
                        )
                        .fetch_all(&postgres2)
                        .await;
                        if let Ok(rows) = rows {
                            let mapping = rows
                                .into_iter()
                                .map(|row| {
                                    (
                                        row.0,
                                        SubscriptionInfo {
                                            level: Level::Plus,
                                            expires_unix: row.2 as _,
                                        },
                                    )
                                })
                                .collect();
                            *cached_subscriptions.write() = mapping;
                        }
                        smol::Timer::after(Duration::from_secs(fastrand::u64(0..5))).await;
                    }
                });

                let _refresh_summary = smolscale::spawn(async move {
                    loop {
                        let fallible = async {
                            let (bridge_secret,): (Vec<u8>,) = sqlx::query_as(
                                "select value from secrets where key = 'bridge_secret'",
                            )
                            .fetch_one(&postgres3)
                            .await?;
                            let qresult: Vec<ExitRecord> = sqlx::query_as("select * from exits")
                                .fetch_all(&postgres3)
                                .await?;

                            let mut exits = qresult
                                .into_iter()
                                .map(|exit| {
                                    ExitDescriptor {
                                        hostname: exit.hostname.into(),
                                        signing_key: ed25519_dalek::PublicKey::from_bytes(
                                            &exit.signing_key,
                                        )
                                        .unwrap(),
                                        country_code: exit.country.into(),
                                        city_code: exit.city.into(),
                                        direct_routes: vec![], // fill in in the future
                                        sosistab_e2e_pk: x25519_dalek::PublicKey::from(
                                            exit.sosistab_key,
                                        ),
                                        allowed_levels: if exit.plus {
                                            vec![Level::Plus]
                                        } else {
                                            vec![Level::Free, Level::Plus]
                                        },
                                        load: 9.99,
                                    }
                                })
                                .collect_vec();
                            {
                                let exec = smol::Executor::new();
                                let mut accum = vec![];
                                for exit in exits.iter_mut() {
                                    accum.push(exec.spawn(async {
                                        let exit_addr =
                                            smol::net::resolve(format!("{}:28080", exit.hostname))
                                                .await?
                                                .first()
                                                .copied()
                                                .context("no dns result for exit")?;
                                        let transport = BridgeExitTransport::new(
                                            *blake3::hash(&bridge_secret).as_bytes(),
                                            exit_addr,
                                        );
                                        let client = BridgeExitClient(transport);
                                        exit.load = client
                                            .load_factor()
                                            .timeout(Duration::from_millis(5000))
                                            .await
                                            .context(format!(
                                                "timeout while asking for load from {}",
                                                exit.hostname
                                            ))??;
                                        anyhow::Ok(())
                                    }));
                                }
                                exec.run(async move {
                                    for a in accum {
                                        if let Err(err) = a.await {
                                            log::warn!("failed: {:?}", err)
                                        }
                                    }
                                })
                                .await
                            }
                            let summ = MasterSummary {
                                exits,
                                bad_countries: vec!["cn".into(), "ir".into()],
                            };
                            *summary_cache.write() = Some(summ);
                            anyhow::Ok(())
                        };
                        if let Err(err) = fallible.await {
                            log::warn!("cannot refresh summary: {:?}", err)
                        }
                        smol::Timer::after(Duration::from_secs(30)).await;
                    }
                });

                loop {
                    smol::Timer::after(Duration::from_secs(fastrand::u64(0..120))).await;

                    // clean up old bridges
                    bridge_store.delete_expired_bridges(200);

                    sqlx::query(
                        "delete from client_events where timestamp > NOW() - interval '7 day'",
                    )
                    .execute(&postgres)
                    .await
                    .unwrap();

                    let (usercount,): (i64,) = sqlx::query_as("select count(distinct id) from auth_logs where last_login > NOW() - interval '1 day'")
                    .fetch_one(& postgres)
                    .await.unwrap();
                    let (subcount,): (i64,) = sqlx::query_as("select count(*) from subscriptions")
                        .fetch_one(&postgres)
                        .await
                        .unwrap();
                    statsd_client.gauge("usercount", usercount as f64);
                    statsd_client.gauge("subcount", subcount as f64);
                }
            })
        };
        Ok(Self {
            captcha_service_url: captcha_service_url.into(),

            mizaru_sk: Default::default(),

            summary_cache,

            epoch_key_cache: Cache::builder()
                .time_to_idle(Duration::from_secs(86400))
                .build(),

            bridge_per_key: Cache::builder()
                .time_to_live(Duration::from_secs(120))
                .build(),

            bridge_store,

            cached_subscriptions,

            announcements_cache: Cache::builder()
                .time_to_live(Duration::from_secs(600))
                .build(),

            premium_route_cache: Cache::builder()
                .time_to_live(Duration::from_secs(120))
                .build(),

            user_id_cache: Cache::builder()
                .time_to_idle(Duration::from_secs(86400))
                .build(),

            postgres,

            statsd_client,

            validate_cache: Cache::builder()
                .time_to_idle(Duration::from_secs(86400))
                .build(),

            // pwd_cache: Cache::builder()
            //     .time_to_idle(Duration::from_secs(86400))
            //     .build(),
            _task,
        })
    }

    /// Obtains the master x25519 key.
    pub async fn get_master_sk(&self) -> anyhow::Result<x25519_dalek::StaticSecret> {
        let mut txn = self.postgres.begin().await?;
        let val: (Vec<u8>,) = sqlx::query_as("select value from secrets where key = 'MASTER'")
            .fetch_one(&mut txn)
            .await?;
        Ok(bincode::deserialize(&val.0).expect("cannot deserialize master SK"))
    }

    /// Obtains the Mizaru signing key.
    pub async fn get_mizaru_sk(&self, level: Level) -> mizaru::SecretKey {
        // the directory to locally cache signing keys
        let mut cache_location = PathBuf::from("/var/tmp/mizaru");
        cache_location.push(match level {
            Level::Free => "free.bin",
            Level::Plus => "plus.bin",
        });
        let postgres = self.postgres.clone();
        let fut_handle = self
            .mizaru_sk
            .entry(level)
            .or_insert_with(move || {
                smolscale::spawn(async move {
                    if let Ok(key) = std::fs::read(&cache_location) {
                        if let Ok(key) = bincode::deserialize(&key) {
                            return key;
                        }
                    }
                    let key_name = match level {
                        Level::Free => "mizaru-master-sk-free",
                        Level::Plus => "mizaru-master-sk-plus",
                    };
                    let mut txn = postgres.begin().await.expect("cannot start txn");
                    let row: Option<(Vec<u8>,)> =
                        sqlx::query_as("select value from secrets where key = $1")
                            .bind(key_name)
                            .fetch_optional(&mut txn)
                            .await
                            .expect("cannot reach db for keys");
                    match row {
                        Some(row) => {
                            let res: mizaru::SecretKey =
                                run_blocking(move || bincode::deserialize(&row.0))
                                    .await
                                    .expect("must deserialize mizaru-master-sk");
                            let _ =
                                std::fs::write(cache_location, bincode::serialize(&res).unwrap());
                            res
                        }
                        None => {
                            todo!("generate a secret key here")
                        }
                    }
                })
                .shared()
            })
            .clone();
        fut_handle.await
    }

    /// Get a per-epoch key.
    pub async fn get_epoch_key(&self, level: Level, epoch: usize) -> rsa::RSAPublicKey {
        self.epoch_key_cache
            .try_get_with((level, epoch), async {
                let mizaru_sk = self.get_mizaru_sk(level).await;
                let public = mizaru_sk.get_subkey(epoch).to_public_key();
                anyhow::Ok(public)
            })
            .await
            .unwrap()
    }

    /// Creates a new user, consuming a captcha answer.
    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
        captcha_id: &str,
        captcha_soln: &str,
    ) -> anyhow::Result<Result<(), RegisterError>> {
        self.create_user_v2(
            Credentials::Password {
                username: username.into(),
                password: password.into(),
            },
            captcha_id,
            captcha_soln,
        )
        .await
    }

    /// Creates a new user, consuming a captcha answer.
    pub async fn create_user_v2(
        &self,
        credentials: Credentials,
        captcha_id: &str,
        captcha_soln: &str,
    ) -> anyhow::Result<Result<(), RegisterError>> {
        if !verify_captcha(&self.captcha_service_url, captcha_id, captcha_soln).await? {
            log::debug!("{} is not soln to {}", captcha_soln, captcha_id);
            return Ok(Err(RegisterError::Other("incorrect captcha".into())));
        }

        if let Credentials::Signature {
            pubkey,
            unix_secs,
            signature,
        } = credentials.clone()
        {
            if !verify_pk_auth(pubkey, unix_secs, &signature) {
                log::debug!("Credentials for {} were not able to be verified", pubkey);
                return Ok(Err(RegisterError::Other(
                    "Invalid keypair credentials".into(),
                )));
            }
        }

        // // TODO atomicity
        if self.get_user_info_v2(credentials.clone()).await?.is_some() {
            return Ok(Err(RegisterError::DuplicateCredentials));
        }

        let mut txn = self.postgres.begin().await?;

        // NOTE: Generate a random meaningless value as placeholders.
        // This will be removed once the `username` and `pwdhash` columns are removed in the future.
        let _rand: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(7)
            .map(char::from)
            .collect();

        let row = sqlx::query(
            "insert into users (createtime) values ($1) on conflict do nothing returning id",
        )
        .bind(Utc::now().naive_utc())
        .fetch_one(&mut txn)
        .await?;
        let user_id: i32 = row.get(0);

        match credentials {
            Credentials::Password { username, password } => {
                if username != username.to_lowercase() || username != username.trim() {
                    return Ok(Err(RegisterError::Other(
                        "username must be lowercase and not contain whitespace".into(),
                    )));
                }
                sqlx::query(
                    "insert into auth_password (user_id, username, pwdhash) values ($1, $2, $3) on conflict do nothing"
                )
                    .bind(user_id)
                    .bind(username.as_str())
                    .bind(hash_libsodium_password(password.as_str()).await)
                    .execute(&mut txn)
                    .await?;
            }
            Credentials::Signature { pubkey, .. } => {
                sqlx::query("insert into auth_pubkey (user_id, pubkey) values ($1, $2) on conflict do nothing")
                    .bind(user_id)
                    .bind(pubkey.0)
                    .execute(&mut txn)
                    .await?;
            }
        }

        txn.commit().await?;

        log::info!("successfully created a new user!");
        Ok(Ok(()))
    }

    /// Obtains a fresh CAPTCHA for user registration.
    pub async fn get_captcha(&self) -> anyhow::Result<Captcha> {
        let captcha_id = generate_captcha(&self.captcha_service_url).await?;
        let png_data = render_captcha_png(&self.captcha_service_url, &captcha_id).await?;
        Ok(Captcha {
            captcha_id,
            png_data,
        })
    }

    /// Deletes a user.
    pub async fn delete_user(
        &self,
        username: &str,
        password: &str,
    ) -> anyhow::Result<Result<(), AuthError>> {
        self.delete_user_v2(Credentials::Password {
            username: username.into(),
            password: password.into(),
        })
        .await
    }

    /// Deletes a user.
    pub async fn delete_user_v2(
        &self,
        credentials: Credentials,
    ) -> anyhow::Result<Result<(), AuthError>> {
        if !self.verify(credentials.clone()).await? {
            return Ok(Err(AuthError::InvalidCredentials));
        }

        let user_id = self.get_user_info_v2(credentials.clone()).await?;
        if let Some(user_id) = user_id {
            let user_id = user_id.userid;
            let mut txn = self.postgres.begin().await?;
            sqlx::query("delete from users where id = $1")
                .bind(user_id)
                .execute(&mut txn)
                .await?;
            txn.commit().await?;

            log::info!("successfully deleted user: {:?}", user_id);
        }

        Ok(Ok(()))
    }

    /// Adds a bridge route. We save this into the routes table, and every now and then we clear the table of really old values.
    pub async fn add_bridge_route(&self, bridge: BridgeDescriptor) -> anyhow::Result<()> {
        let signing_exit = self
            .get_summary()
            .await?
            .exits
            .into_iter()
            .find(|s| s.hostname == bridge.exit_hostname)
            .context(format!(
                "no exit found for hostname: {}",
                bridge.exit_hostname
            ))?;
        // now we verify the signature.
        let signed_msg =
            bincode::serialize(&bridge.clone().tap_mut(|d| d.exit_signature = Bytes::new()))
                .unwrap();
        // log::debug!("to verify: {}", hex::encode(&signed_msg));
        signing_exit
            .signing_key
            .verify_strict(
                &signed_msg,
                &ed25519_dalek::Signature::from_bytes(&bridge.exit_signature)?,
            )
            .context(format!("cannot verify signature for bridge {:?}", bridge))?;
        // we check that the time is okay
        if bridge.update_time + 1000 < (SystemTime::now().duration_since(UNIX_EPOCH)?).as_secs() {
            anyhow::bail!("bridge is too old")
        }

        // save the bridge
        self.bridge_store.add_bridge(&bridge);

        Ok(())
    }

    /// Obtains the summary of the whole state.
    pub async fn get_summary(&self) -> anyhow::Result<MasterSummary> {
        self.summary_cache
            .read()
            .as_ref()
            .cloned()
            .context("summary not available yet")
    }

    /// Obtains a list of bridges, filtered to only the bridges this user should care about.
    pub async fn get_bridges(
        &self,
        token: BlindToken,
        exit: SmolStr,
        validate: bool,
    ) -> anyhow::Result<Vec<BridgeDescriptor>> {
        let is_legacy = if let Some(version) = token.version.clone() {
            let req = VersionReq::parse("<=4.7.13")?;
            let version = Version::parse(version.as_str())
                .context(format!("failed to parse token version {}", version))?;
            req.matches(&version)
        } else {
            // NOTE: probably iOS rather than actually old
            false
        };

        self.statsd_client.incr(&format!(
            "gb_versions.{}",
            token
                .version
                .clone()
                .unwrap_or_else(|| "old".into())
                .replace('.', "-")
        ));

        let opaque_id = blake3::hash(&bincode::serialize(&token).unwrap());
        let bridges_key = blake3::keyed_hash(opaque_id.as_bytes(), exit.as_bytes());
        let bridges = self
            .bridge_per_key
            .try_get_with(bridges_key, async {
                if !self.validate(token.clone()).await && validate {
                    log::warn!("got invalid token in get_bridges");
                    return Ok(vec![]);
                }

                let summary = self.get_summary().await?;
                let exit_record = summary.exits.iter().find(|e| e.hostname == exit);
                let exit_record = if let Some(r) = exit_record {
                    r
                } else {
                    return Ok(vec![]);
                };
                let sosistab2_e2e_key = exit_record.sosistab_e2e_pk;

                let mut all_bridges: Vec<BridgeDescriptor> = self
                    .bridge_store
                    .get_bridges(exit)
                    .iter()
                    .filter_map(|bridge| {
                        let mut bridge = bridge.clone();
                        // NOTE: handle legacy calls by encoding both the pipe-specific cookie and the e2e key
                        let cookie_or_tuple: Bytes = if is_legacy && bridge.protocol.contains("udp")
                        {
                            let cookie_bytes: [u8; 32] = bridge.cookie.as_ref().try_into().ok()?;
                            let cookie = ObfsUdpPublic::from_bytes(cookie_bytes);
                            bincode::serialize(&(cookie, sosistab2_e2e_key))
                                .unwrap()
                                .into()
                        } else {
                            bridge.cookie
                        };
                        bridge.cookie = cookie_or_tuple;
                        Some(bridge)
                    })
                    .collect();

                let premium_routes = self
                    .premium_route_cache
                    .try_get_with((), async {
                        let premium_routes: Vec<(String,)> =
                            sqlx::query_as("select bridge_group from route_premium")
                                .fetch_all(&self.postgres)
                                .await?;
                        let premium_routes: imbl::HashSet<SmolStr> = premium_routes
                            .into_iter()
                            .map(|s| SmolStr::from(s.0.as_str()))
                            .collect();
                        Ok(premium_routes) as anyhow::Result<_>
                    })
                    .await
                    .map_err(|e| anyhow::anyhow!(e))?;
                // sort by rendezvous hashing
                all_bridges.sort_unstable_by_key(|bridge| {
                    *blake3::keyed_hash(
                        opaque_id.as_bytes(),
                        &bincode::serialize(&bridge.endpoint.ip()).unwrap(),
                    )
                    .as_bytes()
                });
                // go through the sorted version, "deduplicating" by the group+protocol pair.
                let mut seen: HashMap<_, usize> = HashMap::new();
                let mut gathered = vec![];
                for bridge in all_bridges {
                    // only show obfsudp bridges if the version number is new enough
                    if !token
                        .version
                        .as_ref()
                        .and_then(|v| Version::parse(v).ok())
                        .map(|v| v >= Version::parse("4.10.0").unwrap())
                        .unwrap_or(false)
                        && bridge.protocol.contains("obfsudp")
                        && !bridge.is_direct
                    {
                        continue;
                    }
                    if token.level == Level::Plus
                        || !premium_routes.contains(bridge.alloc_group.as_str())
                    {
                        let lala = seen
                            .entry((bridge.alloc_group.clone(), bridge.protocol.clone()))
                            .or_default();
                        *lala += 1;
                        if *lala > 2 {
                            continue;
                        }
                        gathered.push(bridge);
                    }
                }
                anyhow::Ok(gathered)
            })
            .await
            .map_err(|e| anyhow::anyhow!(e))?;

        Ok(bridges)
    }

    /// Validates the username and password.
    pub async fn authenticate(
        &self,
        auth_req: &AuthRequest,
    ) -> anyhow::Result<Result<AuthResponse, AuthError>> {
        let v2_request = AuthRequestV2 {
            credentials: Credentials::Password {
                username: auth_req.username.clone(),
                password: auth_req.password.clone(),
            },
            level: auth_req.level,
            epoch: auth_req.epoch,
            blinded_digest: auth_req.blinded_digest.clone(),
        };
        let v2_response = self.authenticate_v2(&v2_request).await?;
        match v2_response {
            Err(err) => Ok(Err(err)),
            Ok(resp) => {
                let response = AuthResponse {
                    user_info: UserInfo {
                        userid: resp.user_info.userid,
                        username: auth_req.username.clone(),
                        subscription: resp.user_info.subscription.clone(),
                    },
                    blind_signature_bincode: resp.blind_signature_bincode,
                };
                Ok(Ok(response))
            }
        }
    }

    pub async fn authenticate_v2(
        &self,
        auth_req: &AuthRequestV2,
    ) -> anyhow::Result<Result<AuthResponseV2, AuthError>> {
        let user_info =
            if let Some(user_info) = self.get_user_info_v2(auth_req.credentials.clone()).await? {
                user_info
            } else {
                return Ok(Err(AuthError::InvalidCredentials));
            };

        // Authenticate
        if !self.verify(auth_req.credentials.clone()).await? {
            return Ok(Err(AuthError::InvalidCredentials));
        }

        if user_info
            .subscription
            .as_ref()
            .map(|s| s.level)
            .unwrap_or(Level::Free)
            != auth_req.level
        {
            return Ok(Err(AuthError::WrongLevel));
        }
        let start = Instant::now();
        let key = self.get_mizaru_sk(auth_req.level).await;
        let real_epoch = mizaru::time_to_epoch(SystemTime::now());
        if real_epoch.abs_diff(auth_req.epoch as usize) > 1 {
            return Ok(Err(AuthError::Other("time way too out of sync".into())));
        }

        // TODO rate limiting

        let mut txn = self.postgres.begin().await?;
        sqlx::query("insert into auth_logs (id, last_login) values ($1, $2)")
            .bind(user_info.userid)
            .bind(Utc::now().naive_utc())
            .execute(&mut txn)
            .await?;

        // let (login_count,): (i64,) = sqlx::query_as(
        //         "select count (*) from (select distinct last_login from auth_logs where id = $1 and last_login + '1 day' > NOW()) as temp",
        //     )
        //     .bind(user_info.userid)
        //     .fetch_one(&mut txn)
        //     .await?;
        // if login_count > 30 {
        //     return Ok(Err(AuthError::TooManyRequests));
        // }

        txn.commit().await?;

        let req = auth_req.clone();
        let response = run_blocking(move || {
            let sig = key.blind_sign(req.epoch as usize, &req.blinded_digest);
            AuthResponseV2 {
                user_info,
                blind_signature_bincode: bincode::serialize(&sig).unwrap().into(),
            }
        })
        .await;
        log::info!("blind_sign took {:?}", start.elapsed());

        Ok(Ok(response))
    }

    pub async fn get_login_url(
        &self,
        credentials: Credentials,
    ) -> anyhow::Result<String, AuthError> {
        match credentials {
            Credentials::Password { username, password } => Ok(format!(
                "https://geph.io/billing/login?next=%2Fbilling%2Fdashboard&uname={}&pwd={}",
                username, password
            )),
            Credentials::Signature {
                pubkey,
                unix_secs,
                signature,
            } => {
                Ok(format!(
                "https://geph.io/billing/login?next=%2Fbilling%2Fdashboard&pkey={}&secs={}&sig={}",
                pubkey, unix_secs, hex::encode(signature)
            ))
            }
        }
    }

    /// Validates a token
    pub async fn validate(&self, token: BlindToken) -> bool {
        let cache_key = blake3::hash(&bincode::serialize(&token).unwrap());
        self.validate_cache
            .get_with(cache_key, async {
                let key = self.get_mizaru_sk(token.level).await.to_public_key();

                key.blind_verify(
                    &token.unblinded_digest,
                    &match bincode::deserialize(&token.unblinded_signature_bincode) {
                        Ok(v) => v,
                        _ => return false,
                    },
                )
            })
            .await
    }

    /// Verifies given credentials
    pub async fn verify(&self, credentials: Credentials) -> anyhow::Result<bool> {
        match credentials {
            Credentials::Password { username, password } => {
                self.verify_password(username.as_str(), password.as_str())
                    .await
            }
            Credentials::Signature {
                pubkey,
                unix_secs,
                signature,
            } => Ok(verify_pk_auth(pubkey, unix_secs, &signature)),
        }
    }

    /// Verifies the password.
    async fn verify_password(&self, username: &str, password: &str) -> anyhow::Result<bool> {
        // log::info!("MISS for username {username}");
        let mut txn = self.postgres.begin().await?;
        let (pwdhash,): (String,) = if let Some(v) =
            sqlx::query_as("select pwdhash from auth_password where username = $1")
                .bind(username)
                .fetch_optional(&mut txn)
                .await?
        {
            v
        } else {
            return Ok(false);
        };
        Ok(verify_libsodium_password(password.to_string(), pwdhash).await)
    }

    /// Gets announcements.
    pub async fn get_announcements(&self) -> String {
        self.announcements_cache
            .try_get_with((), async {
                let resp = reqwest::get("https://rsshub.app/telegram/channel/gephannounce")
                    .compat()
                    .await?;
                let bts = resp.bytes().await?;
                anyhow::Ok(String::from_utf8_lossy(&bts).to_string())
            })
            .await
            .unwrap_or_else(|_| "Failed to fetch announcements".to_string())
    }

    async fn get_user_id(&self, credentials: &Credentials) -> Result<Option<i32>, sqlx::Error> {
        if let Some(val) = self.user_id_cache.get(credentials).await {
            // log::info!("HIT for user id {val}");
            return Ok(Some(val));
        }
        let mut txn = self.postgres.begin().await?;
        let id: Option<(i32,)> = match &credentials {
            Credentials::Password {
                username,
                password: _,
            } => {
                sqlx::query_as("select user_id from auth_password where username = $1")
                    .bind(username.as_str())
                    .fetch_optional(&mut txn)
                    .await?
            }
            Credentials::Signature { pubkey, .. } => {
                sqlx::query_as("select user_id from auth_pubkey where pubkey = $1")
                    .bind(pubkey.0)
                    .fetch_optional(&mut txn)
                    .await?
            }
        };
        txn.commit().await?;
        if let Some(id) = id {
            // log::info!("MISS for user id {}", id.0);
            self.user_id_cache.insert(credentials.clone(), id.0).await;
            Ok(Some(id.0))
        } else {
            Ok(None)
        }
    }

    pub async fn get_user_info_v2(
        &self,
        credentials: Credentials,
    ) -> Result<Option<UserInfoV2>, sqlx::Error> {
        let userid = if let Some(u) = self.get_user_id(&credentials).await? {
            u
        } else {
            return Ok(None);
        };
        let sub_info = self.cached_subscriptions.read().get(&userid).cloned();

        let response = UserInfoV2 {
            userid,
            subscription: sub_info,
        };
        Ok(Some(response))
    }

    pub async fn add_metric(
        &self,
        session: i64,
        data: serde_json::Value,
    ) -> Result<(), sqlx::Error> {
        // let mut txn = self.postgres.begin().await?;

        // sqlx::query(
        //     "insert into client_events (session, timestamp, data) values ($1, $2, $3) on conflict do nothing",
        // )
        // .bind(session)
        // .bind(Utc::now().naive_utc())
        // .bind(data)
        // .execute(&mut txn)
        // .await?;

        // txn.commit().await?;
        Ok(())
    }
}

/// Verify a captcha.
async fn verify_captcha(
    captcha_service: &str,
    captcha_id: &str,
    solution: &str,
) -> anyhow::Result<bool> {
    // call out to the microservice
    let resp = reqwest::get(&format!(
        "{}/solve?id={}&soln={}",
        captcha_service, captcha_id, solution
    ))
    .compat()
    .await?;
    // TODO handle network errors
    Ok(resp.status() == StatusCode::OK)
}

/// Generate a captcha, returning its ID.
async fn generate_captcha(captcha_service: &str) -> anyhow::Result<SmolStr> {
    // call out to the microservice
    let resp = reqwest::get(&format!("{}/new", captcha_service))
        .compat()
        .await?;
    if resp.status() == StatusCode::OK {
        Ok(String::from_utf8_lossy(&resp.bytes().await?).into())
    } else {
        anyhow::bail!("cannot contact captcha microservice to generate")
    }
}

/// Render a captcha as PNG given a captcha service string.
async fn render_captcha_png(captcha_service: &str, captcha_id: &str) -> anyhow::Result<Bytes> {
    // download the captcha from the service
    let resp = reqwest::get(&format!("{}/img/{}", captcha_service, captcha_id))
        .compat()
        .await?;
    if resp.status() == StatusCode::OK {
        Ok(resp.bytes().await?)
    } else {
        anyhow::bail!("cannot concact captcha microservice to render")
    }
}

async fn verify_libsodium_password(password: String, hash: String) -> bool {
    run_blocking(move || {
        let password = password.as_bytes();
        let hash = CString::new(hash).unwrap();
        let res = unsafe {
            libsodium_sys::crypto_pwhash_str_verify(
                hash.as_ptr(),
                password.as_ptr() as _,
                password.len() as u64,
            )
        };
        res == 0
    })
    .await
}

async fn hash_libsodium_password(password: &str) -> String {
    let password = password.as_bytes().to_vec();
    run_blocking(move || {
        let mut output = vec![0u8; 1024];
        let res = unsafe {
            libsodium_sys::crypto_pwhash_str(
                output.as_mut_ptr() as _,
                password.as_ptr() as _,
                password.len() as u64,
                libsodium_sys::crypto_pwhash_OPSLIMIT_INTERACTIVE as u64 / 2,
                libsodium_sys::crypto_pwhash_MEMLIMIT_INTERACTIVE as usize / 2,
            )
        };
        assert_eq!(res, 0);
        let cstr = unsafe { CStr::from_ptr(output.as_ptr() as _) };
        cstr.to_str().unwrap().to_owned()
    })
    .await
}
