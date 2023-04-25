mod bindercore_v2;
mod records;
mod serve;

use env_logger::Env;

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
    #[structopt(default_value = "127.0.0.1:18080", long)]
    listen_http: SocketAddr,
    /// New HTTP listening port
    #[structopt(default_value = "0.0.0.0:28080", long)]
    listen_new: SocketAddr,
    /// NOT USED. Kept so that old systemd scripts do not fail with argument not found.
    #[structopt(long, default_value = "127.0.0.1:12345")]
    gfwreport_addr: SocketAddr,
    #[structopt(long, default_value = "172.105.28.221:8125")]
    /// UDP address of the statsd daemon
    statsd_addr: SocketAddr,
}

fn main() -> anyhow::Result<()> {
    // Stress-tests load balancing as well as forcing upgrades.
    std::thread::spawn(|| loop {
        std::thread::sleep(Duration::from_secs(
            rand::thread_rng().gen_range(3600, 86400),
        ));
        std::process::exit(-1);
    });

    smolscale::block_on(async {
        env_logger::Builder::from_env(Env::default().default_filter_or("geph4_binder=info")).init();
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
