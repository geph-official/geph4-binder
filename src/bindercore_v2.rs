use std::{
    collections::HashSet,
    ffi::{CStr, CString},
    str::FromStr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use async_compat::CompatExt;
use bytes::Bytes;
use chrono::Utc;
use dashmap::DashMap;
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

use moka::sync::Cache;
use once_cell::sync::Lazy;

use rand::{distributions::Alphanumeric, Rng};
use reqwest::StatusCode;
use rusty_pool::ThreadPool;
use semver::{Version, VersionReq};
use smol::Task;
use smol_str::SmolStr;
use smol_timeout::TimeoutExt;
use sosistab2::MuxPublic;
use sqlx::{
    pool::PoolOptions,
    postgres::{PgConnectOptions, PgSslMode},
    PgPool, Row,
};
use tap::Tap;

use crate::{bridge_store::BridgeStore, records::ExitRecord, POOL_SIZE};

pub struct BinderCoreV2 {
    captcha_service_url: SmolStr,

    mizaru_sk: DashMap<Level, Shared<Task<mizaru::SecretKey>>>,

    // caches the network summary
    summary_cache: Cache<(), MasterSummary>,

    // caches the entire req/resp of authentications.
    auth_cache: Cache<AuthRequest, AuthResponse>,

    // caches the entire req/resp of authentications for V2
    auth_cache_v2: Cache<AuthRequestV2, AuthResponseV2>,

    // caches the per-epoch key
    epoch_key_cache: Cache<(Level, usize), rsa::RSAPublicKey>,

    // caches bridges *per key*
    bridge_per_key: Cache<blake3::Hash, Vec<BridgeDescriptor>>,

    // in-memory store for bridge descriptors
    bridge_store: Arc<BridgeStore>,

    // caches *wrong* passwords
    pwd_cache: Cache<(SmolStr, SmolStr), bool>,

    // caches the "premium routes"
    premium_route_cache: Cache<(), imbl::HashSet<SmolStr>>,

    bridge_secret_cache: Cache<(), Vec<u8>>,

    announcements_cache: Cache<(), String>,

    validate_cache: Cache<blake3::Hash, bool>,

    // Postgres
    postgres: PgPool,

    // stats client
    statsd_client: Arc<statsd::Client>,

    _task: Task<()>,
}

impl BinderCoreV2 {
    /// Constructs a BinderCore.
    pub async fn connect(
        database_url: &str,
        captcha_service_url: &str,
        cert: &[u8],
        statsd_client: Arc<statsd::Client>,
    ) -> anyhow::Result<Self> {
        let postgres = PoolOptions::new()
            .max_connections(POOL_SIZE as _)
            .max_lifetime(Duration::from_secs(600))
            .connect_with(
                PgConnectOptions::from_str(database_url)?
                    .ssl_mode(PgSslMode::VerifyFull)
                    .ssl_root_cert_from_pem(cert.to_vec()),
            )
            .await?;

        let bridge_store = Arc::new(BridgeStore::default());

        let _task = {
            let postgres = postgres.clone();
            let statsd_client = statsd_client.clone();
            let bridge_store = bridge_store.clone();
            smolscale::spawn(async move {
                loop {
                    smol::Timer::after(Duration::from_secs(fastrand::u64(0..600))).await;

                    // clean up old bridges
                    bridge_store.delete_expired_bridges(180);

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

            summary_cache: Cache::builder()
                .time_to_live(Duration::from_secs(600))
                .build(),

            auth_cache: Cache::builder()
                .time_to_live(Duration::from_secs(3600))
                .max_capacity(100000)
                .build(),

            auth_cache_v2: Cache::builder()
                .time_to_live(Duration::from_secs(3600))
                .max_capacity(100000)
                .build(),

            epoch_key_cache: Cache::new(10000),

            bridge_per_key: Cache::builder()
                .time_to_live(Duration::from_secs(30))
                .build(),

            bridge_store,

            bridge_secret_cache: Cache::new(100),

            announcements_cache: Cache::builder()
                .time_to_live(Duration::from_secs(10))
                .build(),

            premium_route_cache: Cache::builder()
                .time_to_live(Duration::from_secs(120))
                .build(),

            postgres,

            statsd_client,

            validate_cache: Cache::new(100000),

            pwd_cache: Cache::new(100000),

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
        let mut cache_location = dirs::cache_dir()
            .expect("no cache dir for mizaru")
            .tap_mut(|p| p.push("mizaru"));
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
                                smol::unblock(move || bincode::deserialize(&row.0))
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
        if let Some(v) = self.epoch_key_cache.get(&(level, epoch)) {
            v
        } else {
            let mizaru_sk = self.get_mizaru_sk(level).await;
            let public = mizaru_sk.get_subkey(epoch).to_public_key();
            self.epoch_key_cache.insert((level, epoch), public.clone());
            public
        }
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
        // EMERGENCY
        // return Ok(Err(RegisterError::Other("too many requests".into())));

        if !verify_captcha(&self.captcha_service_url, captcha_id, captcha_soln).await? {
            log::debug!("{} is not soln to {}", captcha_soln, captcha_id);
            return Ok(Err(RegisterError::Other("incorrect captcha".into())));
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

        let user_id = self
            .get_user_info_v2(credentials.clone())
            .await?
            .ok_or(AuthError::InvalidCredentials)?
            .userid;

        let mut txn = self.postgres.begin().await?;
        sqlx::query("delete from users where id = $1")
            .bind(user_id)
            .execute(&mut txn)
            .await?;
        txn.commit().await?;

        log::info!("successfully deleted user: {:?}", user_id);

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
        if let Some(summary) = self.summary_cache.get(&()) {
            Ok(summary)
        } else {
            let bridge_secret = if let Some(bs) = self.bridge_secret_cache.get(&()) {
                bs
            } else {
                let (bridge_secret,): (Vec<u8>,) =
                    sqlx::query_as("select value from secrets where key = 'bridge_secret'")
                        .fetch_one(&self.postgres)
                        .await?;
                self.bridge_secret_cache.insert((), bridge_secret.clone());
                bridge_secret
            };
            let qresult: Vec<ExitRecord> = sqlx::query_as("select * from exits")
                .fetch_all(&self.postgres)
                .await?;

            let mut exits = qresult
                .into_iter()
                .map(|exit| {
                    ExitDescriptor {
                        hostname: exit.hostname.into(),
                        signing_key: ed25519_dalek::PublicKey::from_bytes(&exit.signing_key)
                            .unwrap(),
                        country_code: exit.country.into(),
                        city_code: exit.city.into(),
                        direct_routes: vec![], // fill in in the future
                        sosistab_e2e_pk: x25519_dalek::PublicKey::from(exit.sosistab_key),
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
                        let exit_addr = smol::net::resolve(format!("{}:28080", exit.hostname))
                            .await?
                            .get(0)
                            .copied()
                            .context("no dns result for exit")?;
                        let transport = BridgeExitTransport::new(
                            *blake3::hash(&bridge_secret).as_bytes(),
                            exit_addr,
                        );
                        let client = BridgeExitClient(transport);
                        exit.load = client
                            .load_factor()
                            .timeout(Duration::from_millis(500))
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
            self.summary_cache.insert((), summ.clone());
            Ok(summ)
        }
    }

    /// Obtains a list of bridges, filtered to only the bridges this user should care about.
    pub async fn get_bridges(
        &self,
        token: BlindToken,
        exit: SmolStr,
        validate: bool,
    ) -> anyhow::Result<Vec<BridgeDescriptor>> {
        let is_legacy = if let Some(version) = token.version.clone() {
            let req = VersionReq::parse("<=4.7.13").unwrap();
            let version = Version::parse(version.as_str())
                .expect(format!("failed to parse token version {}", version).as_str());
            req.matches(&version)
        } else {
            // NOTE: only VERY old clients don't have a version set on their auth tokens
            true
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
        if let Some(bridges) = self
            .bridge_per_key
            .get(&blake3::keyed_hash(opaque_id.as_bytes(), exit.as_bytes()))
        {
            return Ok(bridges);
        }
        if !self.validate(token.clone()).await && validate {
            log::warn!("got invalid token in get_bridges");
            return Ok(vec![]);
        }

        let mut txn = self.postgres.begin().await?;
        let sosistab2_e2e_key: (Vec<u8>,) =
            sqlx::query_as("select sosistab_key from exits where hostname = $1")
                .bind(exit.as_str())
                .fetch_one(&mut txn)
                .await?;
        let sosistab2_e2e_key = MuxPublic::from_bytes(
            sosistab2_e2e_key
                .0
                .try_into()
                .expect("e2e key is wrong length"),
        );
        let mut all_bridges: Vec<BridgeDescriptor> = self
            .bridge_store
            .get_bridges()
            .iter()
            .map(|bridge| {
                let mut bridge = bridge.clone();
                // NOTE: handle legacy calls by encoding both the pipe-specific cookie and the e2e key
                let cookie_or_tuple: Bytes = if is_legacy && bridge.protocol.contains("udp") {
                    bincode::serialize(&(bridge.cookie, sosistab2_e2e_key))
                        .unwrap()
                        .into()
                } else {
                    bridge.cookie
                };
                bridge.cookie = cookie_or_tuple;
                bridge
            })
            .collect();

        let premium_routes = if let Some(routes) = self.premium_route_cache.get(&()) {
            routes
        } else {
            let premium_routes: Vec<(String,)> =
                sqlx::query_as("select bridge_group from route_premium")
                    .fetch_all(&self.postgres)
                    .await?;
            let premium_routes: imbl::HashSet<SmolStr> = premium_routes
                .into_iter()
                .map(|s| SmolStr::from(s.0.as_str()))
                .collect();
            self.premium_route_cache.insert((), premium_routes.clone());
            premium_routes
        };
        // sort by rendezvous hashing
        all_bridges.sort_unstable_by_key(|bridge| {
            *blake3::keyed_hash(
                opaque_id.as_bytes(),
                &bincode::serialize(&bridge.endpoint.ip()).unwrap(),
            )
            .as_bytes()
        });
        // go through the sorted version, "deduplicating" by the group+protocol pair.
        let mut seen = HashSet::new();
        let mut gathered = vec![];
        for bridge in all_bridges {
            // only show obfsudp bridges if the version number is new enough
            if !token
                .version
                .as_ref()
                .and_then(|v| Version::parse(v).ok())
                .map(|v| v >= Version::parse("4.7.4").unwrap())
                .unwrap_or(false)
                && bridge.protocol.contains("obfsudp")
                && !bridge.is_direct
            {
                continue;
            }
            if (token.level == Level::Plus || !premium_routes.contains(bridge.alloc_group.as_str()))
                && seen.insert((bridge.alloc_group.clone(), bridge.protocol.clone()))
            {
                gathered.push(bridge);
            }
        }
        self.bridge_per_key.insert(opaque_id, gathered.clone());
        Ok(gathered)
    }

    /// Validates the username and password.
    pub async fn authenticate(
        &self,
        auth_req: &AuthRequest,
    ) -> anyhow::Result<Result<AuthResponse, AuthError>> {
        if let Some(val) = self.auth_cache.get(auth_req) {
            return Ok(Ok(val));
        }

        let user_info = if let Some(user_info) = self.get_user_info_v1(&auth_req.username).await? {
            user_info
        } else {
            return Ok(Err(AuthError::InvalidCredentials));
        };

        if user_info
            .subscription
            .as_ref()
            .map(|s| s.level)
            .unwrap_or(Level::Free)
            != auth_req.level
        {
            return Ok(Err(AuthError::WrongLevel));
        }

        if !self
            .verify_password(&auth_req.username, &auth_req.password)
            .await?
        {
            return Ok(Err(AuthError::InvalidCredentials));
        }
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

        let (login_count,): (i64,) = sqlx::query_as(
                "select count (*) from (select distinct last_login from auth_logs where id = $1 and last_login + '1 day' > NOW()) as temp",
            )
            .bind(user_info.userid)
            .fetch_one(&mut txn)
            .await?;
        if login_count > 30 {
            return Ok(Err(AuthError::TooManyRequests));
        }

        txn.commit().await?;

        let sig = key.blind_sign(auth_req.epoch as usize, &auth_req.blinded_digest);
        let response = AuthResponse {
            user_info,
            blind_signature_bincode: bincode::serialize(&sig).unwrap().into(),
        };
        self.auth_cache.insert(auth_req.clone(), response.clone());
        Ok(Ok(response))
    }

    pub async fn authenticate_v2(
        &self,
        auth_req: &AuthRequestV2,
    ) -> anyhow::Result<Result<AuthResponseV2, AuthError>> {
        if let Some(val) = self.auth_cache_v2.get(auth_req) {
            return Ok(Ok(val));
        }

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

        let (login_count,): (i64,) = sqlx::query_as(
                "select count (*) from (select distinct last_login from auth_logs where id = $1 and last_login + '1 day' > NOW()) as temp",
            )
            .bind(user_info.userid)
            .fetch_one(&mut txn)
            .await?;
        if login_count > 30 {
            return Ok(Err(AuthError::TooManyRequests));
        }

        txn.commit().await?;

        let sig = key.blind_sign(auth_req.epoch as usize, &auth_req.blinded_digest);
        let response = AuthResponseV2 {
            user_info,
            blind_signature_bincode: bincode::serialize(&sig).unwrap().into(),
        };
        self.auth_cache_v2
            .insert(auth_req.clone(), response.clone());
        Ok(Ok(response))
    }

    /// Validates a token
    pub async fn validate(&self, token: BlindToken) -> bool {
        let cache_key = blake3::hash(&bincode::serialize(&token).unwrap());
        if let Some(val) = self.validate_cache.get(&cache_key) {
            return val;
        }
        let key = self.get_mizaru_sk(token.level).await.to_public_key();
        let value = key.blind_verify(
            &token.unblinded_digest,
            &match bincode::deserialize(&token.unblinded_signature_bincode) {
                Ok(v) => v,
                _ => return false,
            },
        );
        self.validate_cache.insert(cache_key, value);
        value
    }

    /// Verifies given credentials
    async fn verify(&self, credentials: Credentials) -> anyhow::Result<bool> {
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
        if let Some(val) = self.pwd_cache.get(&(username.into(), password.into())) {
            return Ok(val);
        }
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
        if verify_libsodium_password(password.to_string(), pwdhash).await {
            self.pwd_cache
                .insert((username.into(), password.into()), true);
            Ok(true)
        } else {
            self.pwd_cache
                .insert((username.into(), password.into()), false);
            Ok(false)
        }
    }

    /// Gets announcements.
    pub async fn get_announcements(&self) -> String {
        if let Some(ann) = self.announcements_cache.get(&()) {
            return ann;
        }
        loop {
            let fallible = async {
                let resp = reqwest::get("https://rsshub.app/telegram/channel/gephannounce").await?;
                let bts = resp.bytes().await?;
                anyhow::Ok(String::from_utf8_lossy(&bts).to_string())
            };
            if let Ok(val) = fallible.await {
                self.announcements_cache.insert((), val.clone());
                return val;
            }
        }
    }

    /// Obtain the user info given the username.
    async fn get_user_info_v1(&self, username: &str) -> Result<Option<UserInfo>, sqlx::Error> {
        let mut txn = self.postgres.begin().await?;
        let res: Option<(i32, String, String)> =
            sqlx::query_as("select id,username,pwdhash from users_legacy where username = $1")
                .bind(username)
                .fetch_optional(&mut txn)
                .await?;
        let (userid, username, _) = if let Some(res) = res {
            res
        } else {
            return Ok(None);
        };
        let plan_row: Option<(String, f64)> = sqlx::query_as(
            "select plan, extract(epoch from expires) from subscriptions where id = $1",
        )
        .bind(userid)
        .fetch_optional(&mut txn)
        .await?;

        Ok(Some(UserInfo {
            userid,
            username: username.into(),

            subscription: plan_row.map(|row| SubscriptionInfo {
                level: Level::Plus,
                expires_unix: row.1 as i64,
            }),
        }))
    }

    async fn get_user_info_v2(
        &self,
        credentials: Credentials,
    ) -> Result<Option<UserInfoV2>, sqlx::Error> {
        let mut txn = self.postgres.begin().await?;
        let res: Option<(i32,)> = match credentials {
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
                    .bind(pubkey.to_string())
                    .fetch_optional(&mut txn)
                    .await?
            }
        };

        println!("get user info res: {:?}", res);

        let (userid,) = if let Some(res) = res {
            res
        } else {
            return Ok(None);
        };

        let plan_row: Option<(String, f64)> = sqlx::query_as(
            "select plan, extract(epoch from expires) from subscriptions where id = $1",
        )
        .bind(userid)
        .fetch_optional(&mut txn)
        .await?;

        Ok(Some(UserInfoV2 {
            userid,
            subscription: plan_row.map(|row| SubscriptionInfo {
                level: Level::Plus,
                expires_unix: row.1 as i64,
            }),
        }))
    }
}

/// Verify a captcha.
async fn verify_captcha(
    captcha_service: &str,
    captcha_id: &str,
    solution: &str,
) -> anyhow::Result<bool> {
    println!(
        "verify_captcha({}, {}, {})",
        captcha_service, captcha_id, solution
    );
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
    let resp = reqwest::get(&format!("{}/new", captcha_service)).await?;
    if resp.status() == StatusCode::OK {
        Ok(String::from_utf8_lossy(&resp.bytes().await?).into())
    } else {
        anyhow::bail!("cannot contact captcha microservice to generate")
    }
}

/// Render a captcha as PNG given a captcha service string.
async fn render_captcha_png(captcha_service: &str, captcha_id: &str) -> anyhow::Result<Bytes> {
    // download the captcha from the service
    let resp = reqwest::get(&format!("{}/img/{}", captcha_service, captcha_id)).await?;
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
                password.as_ptr() as *const i8,
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
                output.as_mut_ptr() as *mut i8,
                password.as_ptr() as *const i8,
                password.len() as u64,
                libsodium_sys::crypto_pwhash_OPSLIMIT_INTERACTIVE as u64 / 2,
                libsodium_sys::crypto_pwhash_MEMLIMIT_INTERACTIVE as usize / 2,
            )
        };
        assert_eq!(res, 0);
        let cstr = unsafe { CStr::from_ptr(output.as_ptr() as *const i8) };
        cstr.to_str().unwrap().to_owned()
    })
    .await
}

async fn run_blocking<T: Send + Sync + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    static POOL: Lazy<ThreadPool> =
        Lazy::new(|| ThreadPool::new(1, num_cpus::get(), Duration::from_secs(10)));
    let (mut send, recv) = async_oneshot::oneshot();
    POOL.execute(move || {
        let t = f();
        let _ = send.send(t);
    });
    recv.await.unwrap()
}
