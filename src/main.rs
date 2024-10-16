mod config;
mod grpc;
mod inference_api;
mod inference_api_providers;
mod management_api;
mod management_api_providers;

#[cfg(feature = "github")]
use crate::management_api_providers::github_api::github_api::GithubApi;

#[cfg(feature = "llamafile")]
use crate::inference_api_providers::llamafile::LlamaFile;

use config::global_config;
use grpc::{FirewallServer, FirewallService, Server};
use std::{error::Error, net::IpAddr, str::FromStr, time::Duration};
use tracing::subscriber::set_global_default;
use tracing_panic::panic_hook;
use tracing_subscriber::FmtSubscriber;

const VERSION: &str = "1.0.0";

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
    let addr = server_addr_str
        .parse()
        .unwrap_or_else(|_| panic!("Failed to parse socket address {}", server_addr_str));

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
                .map(|f| {
                    IpAddr::from_str(f)
                        .unwrap_or_else(|_| panic!("{} is not a valid IP address", f))
                })
                .collect(),
        )
        // Set model completion url
        .set_url(format!(
            "{}://{}/completion",
            global_config.llm_proto(),
            llm_addr_str,
        ))
        // Set evaluation command, should be external program with params `prog.exe {malignity} {severity} {utility} {expectance}`
        .set_eval_cmd(global_config.evaluator_cmd().clone())
        // Set timeout
        .set_timeout_duration(Duration::from_secs(5));

    #[cfg(feature = "github")]
    firewall
        // Set github as the management api
        .set_management_api(management_api::ManagementApis::GithubApi(GithubApi::new()));

    #[cfg(feature = "llamafile")]
    firewall.set_inference_api(inference_api::InferenceApis::LlamaFile(LlamaFile::new(
        llm_addr_str.clone(),
    )));

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
