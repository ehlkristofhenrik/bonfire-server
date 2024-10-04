use getset::Getters;
use lazy_static::lazy_static;
use serde::Deserialize;
use std::{fs::read_to_string, str::FromStr};
use tracing::warn;

// #[cfg(feature = "github")]
use crate::api_providers::github_api::github_api::GithubApiConfig;

lazy_static! {
    pub static ref global_config: Config = serde_json::from_str(
        &read_to_string("config.json").unwrap_or_default()
    )
    .unwrap_or_else(|_| {
        warn!("Failed to load config, using default configuration.");
        Config::default()
    });
}

#[derive(Deserialize, Getters, getset::CopyGetters)]
pub struct Config {
    #[getset(get = "pub")]
    server_addr: NetPair,

    #[getset(get = "pub")]
    llm_addr: NetPair,

    #[getset(get = "pub")]
    llm_proto: String,

    #[getset(get = "pub")]
    allowed_users: Vec<String>,

    #[getset(get = "pub")]
    allowed_ip_addrs: Vec<String>,

    #[getset(get = "pub")]
    evaluator_cmd: String,

    // #[cfg(feature = "github")]
    #[getset(get = "pub")]
    github_api_config: GithubApiConfig,
}

#[derive(Deserialize, Getters)]
pub struct NetPair {
    #[getset(get = "pub")]
    ip: String,

    #[getset(get = "pub")]
    port: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_addr: NetPair {
                ip: String::from_str("127.0.0.1").expect("Failed to load default config.toml"),
                port: 8888,
            },
            llm_addr: NetPair {
                ip: String::from_str("127.0.0.1").expect("Failed to load default config.toml"),
                port: 8080,
            },
            llm_proto: String::from_str("http").expect("Failed to load default config.toml"),
            allowed_users: vec!["root".to_string()],
            allowed_ip_addrs: vec!["127.0.0.1".to_string(), "::1".to_string()],
            evaluator_cmd: "".to_string(),
            github_api_config: GithubApiConfig::default(),
        }
    }
}
