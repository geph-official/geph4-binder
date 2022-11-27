use std::{
    collections::HashSet,
    ffi::{CStr, CString},
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use async_compat::CompatExt;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use futures_util::{future::Shared, FutureExt};

use geph4_protocol::binder::protocol::{
    AuthError, AuthRequest, AuthResponse, BlindToken, BridgeDescriptor, Captcha, ExitDescriptor,
    Level, MasterSummary, RegisterError, SubscriptionInfo, UserInfo,
};
use itertools::Itertools;
use moka::sync::Cache;
use once_cell::sync::Lazy;
use reqwest::StatusCode;
use rusty_pool::ThreadPool;
use smol::Task;
use smol_str::SmolStr;
use sqlx::{
    pool::PoolOptions,
    postgres::{PgConnectOptions, PgSslMode},
    PgPool,
};
use tap::Tap;

use crate::POOL_SIZE;

pub struct BinderCoreV2 {
    captcha_service_url: SmolStr,
    mizaru_sk: DashMap<Level, Shared<Task<mizaru::SecretKey>>>,

    // caches the network summary
    summary_cache: Cache<(), MasterSummary>,
    // caches the correct password of a user. prevents DoS attacks
    pwd_cache: Cache<SmolStr, SmolStr>,
    // caches the per-epoch key
    epoch_key_cache: Cache<(Level, usize), rsa::RSAPublicKey>,

    // caches bridges *per exit*
    bridge_per_exit_cache: Cache<SmolStr, Vec<BridgeDescriptor>>,

    // Postgres
    postgres: PgPool,
}

impl BinderCoreV2 {
    /// Constructs a BinderCore.
    pub async fn connect(
        database_url: &str,
        captcha_service_url: &str,
        cert: &[u8],
    ) -> anyhow::Result<Self> {
        let postgres = PoolOptions::new()
            .max_connections(POOL_SIZE as _)
            .max_lifetime(Duration::from_secs(600))
            .connect_with(
                PgConnectOptions::from_str(database_url)?
                    .statement_cache_capacity(0) // pgbouncer compat
                    .ssl_mode(PgSslMode::VerifyFull)
                    .ssl_root_cert_from_pem(cert.to_vec()),
            )
            .await?;
        Ok(Self {
            captcha_service_url: captcha_service_url.into(),
            mizaru_sk: Default::default(),

            summary_cache: Cache::builder()
                .time_to_live(Duration::from_secs(10))
                .build(),
            pwd_cache: Cache::builder()
                .time_to_live(Duration::from_secs(60))
                .max_capacity(100000)
                .build(),
            epoch_key_cache: Cache::new(10000),
            bridge_per_exit_cache: Cache::builder()
                .time_to_live(Duration::from_secs(60))
                .build(),

            postgres,
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
        if !verify_captcha(&self.captcha_service_url, captcha_id, captcha_soln).await? {
            log::debug!("{} is not soln to {}", captcha_soln, captcha_id);
            return Ok(Err(RegisterError::Other("incorrect captcha".into())));
        }
        // TODO atomicity
        if self.get_user_info(username).await?.is_some() {
            return Ok(Err(RegisterError::DuplicateUsername));
        }
        let mut txn = self.postgres.begin().await?;
        sqlx::query(
            "insert into users (username, pwdhash, freebalance, createtime) values ($1, $2, $3, $4)",
        )
        .bind(username)
        .bind(hash_libsodium_password(password).await)
        .bind(1000i32)
        .bind(Utc::now().naive_utc())
        .execute(&mut txn)
        .await?;
        txn.commit().await?;
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
        if !self.verify_password(username, password).await? {
            return Ok(Err(AuthError::InvalidUsernameOrPassword));
        }
        let mut txn = self.postgres.begin().await?;
        sqlx::query("delete from users where username = $1")
            .bind(username)
            .execute(&mut txn)
            .await?;
        txn.commit().await?;
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
            .context("no such exit")?;
        // now we verify the signature.
        let signed_msg =
            bincode::serialize(&bridge.clone().tap_mut(|d| d.exit_signature = Bytes::new()))
                .unwrap();
        signing_exit.signing_key.verify_strict(
            &signed_msg,
            &ed25519_dalek::Signature::from_bytes(&bridge.exit_signature)?,
        )?;
        // we check that the time is okay
        if bridge.update_time + 1000 < (SystemTime::now().duration_since(UNIX_EPOCH)?).as_secs() {
            anyhow::bail!("too old")
        }
        // insert into the system
        let mut txn = self.postgres.begin().await?;
        // HACK: we encode the protocol into the allocation group name
        sqlx::query("insert into routes (hostname, sosistab_pubkey, bridge_address, bridge_group, update_time) values ($1, $2, $3, $4, $5) on conflict (bridge_address) do
        update set hostname = excluded.hostname, sosistab_pubkey = excluded.sosistab_pubkey, bridge_group = excluded.bridge_group, update_time = excluded.update_time")
        .bind(bridge.exit_hostname.as_str())
        .bind(bridge.sosistab_key.to_bytes().to_vec())
        .bind(bridge.endpoint.to_string())
        .bind(format!("{}!!{}", bridge.alloc_group, bridge.protocol))
        .bind(DateTime::<Utc>::from(UNIX_EPOCH + Duration::from_secs(bridge.update_time)).naive_utc())
        .execute(&mut txn).await?;
        txn.commit().await?;
        Ok(())
    }

    /// Obtains the summary of the whole state.
    pub async fn get_summary(&self) -> anyhow::Result<MasterSummary> {
        if let Some(summary) = self.summary_cache.get(&()) {
            Ok(summary)
        } else {
            let mut txn = self.postgres.begin().await?;
            let qresult: Vec<(String, [u8; 32], String, String, [u8; 32], bool)> = sqlx::query_as(
                "select hostname,signing_key,country,city,sosistab_key,plus from exits",
            )
            .fetch_all(&mut txn)
            .await?;
            let exits = qresult
                .into_iter()
                .map(|row| {
                    ExitDescriptor {
                        hostname: row.0.into(),
                        signing_key: ed25519_dalek::PublicKey::from_bytes(&row.1).unwrap(),
                        country_code: row.2.into(),
                        city_code: row.3.into(),
                        direct_routes: vec![], // fill in in the future
                        legacy_direct_sosistab_pk: x25519_dalek::PublicKey::from(row.4),
                        allowed_levels: if row.5 {
                            vec![Level::Plus]
                        } else {
                            vec![Level::Free, Level::Plus]
                        },
                    }
                })
                .collect_vec();
            Ok(MasterSummary {
                exits,
                bad_countries: vec!["cn".into(), "ir".into()],
            })
        }
    }

    /// Obtains a list of bridges, filtered to only the bridges this user should care about.
    pub async fn get_bridges(
        &self,
        token: BlindToken,
        exit: SmolStr,
    ) -> anyhow::Result<Vec<BridgeDescriptor>> {
        let opaque_id = blake3::hash(&bincode::serialize(&token).unwrap());
        if !self.validate(token).await {
            log::warn!("got invalid token in get_bridges");
            return Ok(vec![]);
        }
        // first, we get *all* the bridges that belong to this exit. this is not particularly efficient, but that's somewhat okay
        let mut all_bridges = {
            if let Some(bunch) = self.bridge_per_exit_cache.get(&exit) {
                bunch
            } else {
                let mut txn = self.postgres.begin().await?;
                let rows: Vec<(String, [u8; 32], String, String, f64)> = sqlx::query_as("select hostname, sosistab_pubkey, bridge_address, bridge_group, extract(epoch from update_time) from routes where hostname = $1").bind(exit.as_str()).fetch_all(&mut txn).await?;
                let result: Vec<BridgeDescriptor> = rows
                    .into_iter()
                    .map(
                        |(hostname, sosistab_pubkey, bridge_address, bridge_group, update_time)| {
                            BridgeDescriptor {
                                is_direct: false,
                                protocol: if let Some((_, right)) = bridge_group.split_once("!!") {
                                    right.into()
                                } else {
                                    "sosistab".into()
                                },
                                endpoint: bridge_address
                                    .parse()
                                    .expect("unparseable bridge address"),
                                sosistab_key: x25519_dalek::PublicKey::from(sosistab_pubkey),
                                exit_hostname: hostname.into(),
                                alloc_group: if let Some((left, _)) = bridge_group.split_once("!!")
                                {
                                    left.into()
                                } else {
                                    bridge_group.into()
                                },
                                update_time: update_time as u64,
                                exit_signature: Bytes::new(), // it's not like the client actually checks this lol
                            }
                        },
                    )
                    .collect();
                self.bridge_per_exit_cache.insert(exit, result.clone());
                result
            }
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
            if seen.insert((bridge.alloc_group.clone(), bridge.protocol.clone())) {
                gathered.push(bridge);
            }
        }
        Ok(gathered)
    }

    /// Validates the username and password.
    pub async fn authenticate(
        &self,
        auth_req: &AuthRequest,
    ) -> anyhow::Result<Result<AuthResponse, AuthError>> {
        let user_info = if let Some(user_info) = self.get_user_info(&auth_req.username).await? {
            user_info
        } else {
            return Ok(Err(AuthError::InvalidUsernameOrPassword));
        };
        if !self
            .verify_password(&auth_req.username, &auth_req.password)
            .await?
        {
            return Ok(Err(AuthError::InvalidUsernameOrPassword));
        }
        let key = self.get_mizaru_sk(auth_req.level).await;
        let real_epoch = mizaru::time_to_epoch(SystemTime::now());
        if real_epoch.abs_diff(auth_req.epoch as usize) > 1 {
            return Ok(Err(AuthError::Other("time way too out of sync".into())));
        }

        // TODO rate limiting

        let sig = key.blind_sign(auth_req.epoch as usize, &auth_req.blinded_digest);
        Ok(Ok(AuthResponse {
            user_info,
            blind_signature_bincode: bincode::serialize(&sig).unwrap().into(),
        }))
    }

    /// Validates a token
    pub async fn validate(&self, token: BlindToken) -> bool {
        let key = self.get_mizaru_sk(token.level).await.to_public_key();
        key.blind_verify(
            &token.unblinded_digest,
            &match bincode::deserialize(&token.unblinded_signature_bincode) {
                Ok(v) => v,
                _ => return false,
            },
        )
    }

    /// Verifies the password.
    async fn verify_password(&self, username: &str, password: &str) -> anyhow::Result<bool> {
        if self
            .pwd_cache
            .get(username)
            .map(|known| known == password)
            .unwrap_or_default()
        {
            return Ok(true);
        }
        let mut txn = self.postgres.begin().await?;
        let (pwdhash,): (String,) = sqlx::query_as("select pwdhash from users where username = $1")
            .bind(username)
            .fetch_one(&mut txn)
            .await?;
        if verify_libsodium_password(password.to_string(), pwdhash).await {
            self.pwd_cache.insert(username.into(), password.into());
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Obtain the user info given the username.
    async fn get_user_info(&self, username: &str) -> Result<Option<UserInfo>, sqlx::Error> {
        let mut txn = self.postgres.begin().await?;
        let res: Option<(i32, String, String)> =
            sqlx::query_as("select id,username,pwdhash from users where username = $1")
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
}

/// Verify a captcha.
async fn verify_captcha(
    captcha_service: &str,
    captcha_id: &str,
    solution: &str,
) -> anyhow::Result<bool> {
    log::debug!(
        "verify_captcha({}, {}, {})",
        captcha_service,
        captcha_id,
        solution
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
                libsodium_sys::crypto_pwhash_OPSLIMIT_INTERACTIVE as u64,
                libsodium_sys::crypto_pwhash_MEMLIMIT_INTERACTIVE as usize,
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