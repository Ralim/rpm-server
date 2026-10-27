use clap::Parser;
use rpm_server::config::Config;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::parse();
    if config.healthcheck {
        let listen = config.listen;
        println!(
            "{}",
            tokio::task::spawn_blocking(move || rpm_server::health::check(listen)).await??
        );
        return Ok(());
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    rpm_server::run(config).await
}
