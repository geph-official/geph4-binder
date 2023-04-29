mod bindercore_v2;
mod bridge_store;
mod records;
mod serve;

use env_logger::Env;

use log::LevelFilter;
use mimalloc::MiMalloc;

use rand::Rng;

use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use structopt::StructOpt;

use crate::serve::start_server;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

const POOL_SIZE: usize = 12;

#[derive(Debug, StructOpt)]
pub struct Opt {
    /// PostgreSQL database URL
    #[structopt(long)]
    database: String,
    /// Path to database connection CA file
    #[structopt(long)]
    database_ca_cert: PathBuf,
    /// Captcha service
    #[structopt(default_value = "https://single-verve-156821.ew.r.appspot.com", long)]
    captcha_endpoint: String,
    /// NOT USED. Kept so that old systemd scripts do not fail with argument not found.
    #[allow(unused)]
    #[structopt(default_value = "127.0.0.1:18080", long)]
    listen_http: SocketAddr,
    /// New HTTP listening port
    #[structopt(default_value = "0.0.0.0:28080", long)]
    listen_new: SocketAddr,
    /// NOT USED. Kept so that old systemd scripts do not fail with argument not found.
    #[allow(unused)]
    #[structopt(long, default_value = "127.0.0.1:12345")]
    gfwreport_addr: SocketAddr,
    #[structopt(long, default_value = "172.105.28.221:8125")]
    /// UDP address of the statsd daemon
    statsd_addr: SocketAddr,
}

fn main() -> anyhow::Result<()> {
    smolscale::block_on(async {
        env_logger::Builder::new()
            .format(|buf, record| {
                use std::io::Write;
                writeln!(
                    buf,
                    "{}:{} {} [{}] - {}",
                    record.file().unwrap_or("unknown"),
                    record.line().unwrap_or(0),
                    chrono::Local::now().format("%Y-%m-%dT%H:%M:%S"),
                    record.level(),
                    record.args()
                )
            })
            .filter(Some("geph4_binder"), LevelFilter::Info)
            .init();

        let opt = Opt::from_args();

        log::info!("geph4-binder starting with:");

        let statsd_client = Arc::new(statsd::Client::new(opt.statsd_addr, "geph4.binder").unwrap());
        let core_v2 = bindercore_v2::BinderCoreV2::connect(
            &opt.database,
            &opt.captcha_endpoint,
            &std::fs::read(&opt.database_ca_cert)?,
            statsd_client.clone(),
        )
        .await?;

        log::info!("core v2 initialized");

        let _statsd_client = statsd_client.clone();
        start_server(core_v2, opt).await?;

        Ok(())
    })
}
