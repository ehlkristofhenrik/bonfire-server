mod api_providers;
mod config;
mod grpc;
mod llama;
mod management_api;

use config::global_config;
use grpc::{FirewallServer, FirewallService, Server};
use std::{error::Error, net::IpAddr, str::FromStr};
use tracing::subscriber::set_global_default;
use tracing_panic::panic_hook;
use tracing_subscriber::FmtSubscriber;

// #[cfg(f
use crate::api_providers::github_api::github_api::GithubApi;

const VERSION: &'static str = "1.0.0";

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Get config addresses
    let server_addr = global_config.server_addr();
    let llm_addr = global_config.llm_addr();

    // Create socket addresses
    let server_addr_str = format!("{}:{}", server_addr.ip(), server_addr.port());
    let llm_addr_str = format!("{}:{}", llm_addr.ip(), llm_addr.port());

    // Initialize logging service
    let subscriber = FmtSubscriber::builder()
        .with_ansi(true)
        .pretty()
        .with_line_number(true)
        .finish();

    // Set default logger
    set_global_default(subscriber).expect("Failed to set logging subscriber");

    // Set panic handler to logger
    std::panic::set_hook(Box::new(panic_hook));

    // Parse server address
    let addr = server_addr_str.parse().expect(&format!(
        "Failed to parse socket address {}",
        server_addr_str
    ));

    // Create firewall service
    let mut firewall = FirewallService::default();
    firewall
        // Set allowed users
        .set_allowed_users(global_config.allowed_users().clone())
        // Set allowed ip addresses
        .set_allowed_ip_addrs(
            global_config
                .allowed_ip_addrs()
                .iter()
                .map(|f| IpAddr::from_str(f).expect(&format!("{} is not a valid IP address", f)))
                .collect(),
        )
        // Set model completion url
        .set_url(format!(
            "{}://{}/completion",
            global_config.llm_proto(),
            llm_addr_str,
        ));

    // Query model for health information
    let health: serde_json::Value = reqwest::get(format!(
        "{}://{}/health",
        global_config.llm_proto(),
        llm_addr_str
    ))
    .await
    .expect("Failed to health check service")
    .json()
    .await
    .expect("Failed to parse health information from LLM service");

    // Check if LLM service is up
    match health["status"].as_str() {
        Some("ok") => {}
        Some("error") => {
            panic!("LLM service sent error status");
        }
        Some("model loading") => {
            panic!("LLM has not been initialized yet");
        }
        _ => {
            panic!("Health status invalid");
        }
    }

    // Display banner
    println!(
        include_str!("../static/ascii_art.txt"),
        VERSION, server_addr_str, llm_addr_str
    );

    // Start gRPC server
    Server::builder()
        .add_service(FirewallServer::new(firewall))
        .serve(addr)
        .await?;

    Ok(())
}
