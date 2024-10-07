mod proto {
    tonic::include_proto!("secu_score");
}

#[cfg(not(test))]
use crate::llama::query_secu_score;

#[cfg(test)]
use crate::llama::*;

use crate::{config::global_config, management_api::ManagementApis};

use getset::Setters;
use proto::firewall_server::Firewall;
pub use proto::firewall_server::FirewallServer;
use proto::{FirewallReply, FirewallRequest};
use ring::constant_time::verify_slices_are_equal;
use core::error;
use std::net::IpAddr;
pub use tonic::transport::Server;
use tonic::{Response, Status};
use std::process::Command;
use tracing::{error, warn};
use std::time::{ Instant, Duration };

#[derive(Default, Setters)]
pub struct FirewallService {
    #[getset(set = "pub")]
    allowed_ip_addrs: Vec<IpAddr>,

    #[getset(set = "pub")]
    allowed_users: Vec<String>,

    #[getset(set = "pub")]
    url: String,

    #[getset(set = "pub")]
    management_api: ManagementApis,

    #[getset(set="pub")]
    eval_cmd: String,

    #[getset(set = "pub")]
    timeout_duration: Duration,
}

#[tonic::async_trait]
impl Firewall for FirewallService {
    // Checks for malicious commands
    async fn check(
        &self,
        request: tonic::Request<FirewallRequest>,
    ) -> Result<tonic::Response<FirewallReply>, tonic::Status> {
        // Get users ip address
        let Some(remote_addr) = request.remote_addr() else {
            error!("Ip address not found for request");
            return Err(Status::invalid_argument("Ip address not found"));
        };

        // Get request body
        let request: &FirewallRequest = request.get_ref();

        let user_str: &str = request.user.as_str();

        // Query user profile
        let (role, issues) = tokio::join!(
            self.management_api.get_user_profile(user_str),
            self.management_api.get_tasks_for_user(user_str)
        );

        let Ok(role)= role else {
            error!("Failed to query user role for {} at {:?}", user_str, &remote_addr.ip());
            return Err(Status::internal("Failed to query user role"));
        };
        let Ok(issues) = issues else {
            error!("Failed to query issues for {} at {:?}", user_str, &remote_addr.ip());
            return Err(Status::internal("Faliled to query issues"));
        };

        // Get username string as bytes for const-time comparoson check
        // NOTE! This is important to avoid timing attacks
        let user_bytes = request.user.as_bytes();

        // Check if user is in allowed list
        let user_match = self
            .allowed_users
            .iter()
            .any(|user| verify_slices_are_equal(user.as_bytes(), user_bytes).is_ok());

        // Check if ip is in allowed list
        let ip_match = self.allowed_ip_addrs.contains(&remote_addr.ip());

        // Close connection if either ip or username does not match
        // NOTE! This is important to check for both to avoid timing attacks
        if !user_match || !ip_match {
            error!("Allowlist does not include {} at {:?} ip: {} user: {}", user_str, &remote_addr.ip(), ip_match, user_match);
            return Ok(tonic::Response::new(FirewallReply { allowed: false }));
        }

        // Query the score from the LLM
        #[cfg(not(test))]
        let Ok(score) = query_secu_score(
            self.url.clone(),
            request.command.clone(),
            request.user.clone(),
            request.path.clone(),
            issues,
            role,
        )
        .await
        else {
            error!("Permission denied for {:?}", &remote_addr.ip());
            return Err(Status::permission_denied("You shall not pass"));
        };

        #[cfg(test)]
        let Ok(score) = Result::<SecuScore, ()>::Ok(SecuScore::default()) else {
            todo!();
        };

        // TODO! Compute the score

        let now = Instant::now();

        let cmd_str: Vec<&str> = self.eval_cmd.split(" ").collect();

        let mut cmd = Command::new(cmd_str[0]).args(&cmd_str[1..]).spawn()?;

        let status = loop {
            if now.elapsed() > self.timeout_duration {
                error!("Timeout exceeded");
                break None;
            }

            match cmd.try_wait() {
                Ok(Some(status)) => {
                    break Some(status.success());
                },
                Ok(None) => {},
                Err(_) => {
                    break None;
                }
            }
        };

        let Some(status) = status else {
            error!("Failed to calculate result for {} at {:?}", user_str, &remote_addr.ip());
            return Err(Status::internal("Failed to calculate result"));
        };

        Ok(Response::new(FirewallReply { allowed: status }))
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::str::FromStr;

    use tonic::transport::server::TcpConnectInfo;
    use tonic::Request;

    use super::*;

    #[tokio::test]
    async fn test_firewall_check_ok() {
        // Construct service
        let mut firewall: FirewallService = FirewallService::default();
        firewall.set_allowed_ip_addrs(vec![IpAddr::from_str("127.0.0.1").unwrap()]);
        firewall.set_allowed_users(vec!["bob".to_string()]);
        firewall.set_timeout_duration(Duration::from_secs(1000));

        firewall.set_eval_cmd("ls".to_string());

        // Create request
        let mut req = Request::new(FirewallRequest {
            command: "ls".to_string(),
            path: "/".to_string(),
            user: "bob".to_string(),
        });

        // Set ip addr
        req.extensions_mut()
            .insert::<TcpConnectInfo>(TcpConnectInfo {
                local_addr: Some(SocketAddr::from_str("127.0.0.1:2345").unwrap()),
                remote_addr: Some(SocketAddr::from_str("127.0.0.1:2345").unwrap()),
            });

        // Get result
        let res = firewall.check(req).await;

        // Assertions
        assert!(res.is_ok());
        let res = res.ok();
        assert!(res.is_some());
        let res = res.unwrap();
        let res = res.get_ref();
        assert!(res.allowed);
    }

    #[tokio::test]
    async fn test_firewall_check_bad_user() {
        // Construct service
        let mut firewall: FirewallService = FirewallService::default();
        firewall.set_allowed_ip_addrs(vec![IpAddr::from_str("127.0.0.1").unwrap()]);
        firewall.set_allowed_users(vec!["mary".to_string()]);

        // Create request
        let mut req = Request::new(FirewallRequest {
            command: "ls".to_string(),
            path: "/".to_string(),
            user: "bob".to_string(),
        });

        // Set ip addr
        req.extensions_mut()
            .insert::<TcpConnectInfo>(TcpConnectInfo {
                local_addr: Some(SocketAddr::from_str("127.0.0.1:2345").unwrap()),
                remote_addr: Some(SocketAddr::from_str("127.0.0.1:2345").unwrap()),
            });

        // Get result
        let res = firewall.check(req).await;

        // Assertions
        assert!(res.is_ok());
        let res = res.ok();
        assert!(res.is_some());
        let res = res.unwrap();
        let res = res.get_ref();
        assert!(!res.allowed);
    }

    #[tokio::test]
    async fn test_firewall_check_bad_ip() {
        // Construct service
        let mut firewall: FirewallService = FirewallService::default();
        firewall.set_allowed_ip_addrs(vec![IpAddr::from_str("192.128.12.3").unwrap()]);
        firewall.set_allowed_users(vec!["bob".to_string()]);

        // Create request
        let mut req = Request::new(FirewallRequest {
            command: "ls".to_string(),
            path: "/".to_string(),
            user: "bob".to_string(),
        });

        // Set ip addr
        req.extensions_mut()
            .insert::<TcpConnectInfo>(TcpConnectInfo {
                local_addr: Some(SocketAddr::from_str("127.0.0.1:2345").unwrap()),
                remote_addr: Some(SocketAddr::from_str("127.0.0.1:2345").unwrap()),
            });

        // Get result
        let res = firewall.check(req).await;

        // Assertions
        assert!(res.is_ok());
        let res = res.ok();
        assert!(res.is_some());
        let res = res.unwrap();
        let res = res.get_ref();
        assert!(!res.allowed);
    }

    #[tokio::test]
    async fn test_firewall_check_timeout() {
        // Construct service
        let mut firewall: FirewallService = FirewallService::default();
        firewall.set_allowed_ip_addrs(vec![IpAddr::from_str("192.128.12.3").unwrap()]);
        firewall.set_allowed_users(vec!["bob".to_string()]);
        firewall.set_timeout_duration(Duration::from_secs(0));

        firewall.set_eval_cmd("sleep 4".to_string());

        // Create request
        let mut req = Request::new(FirewallRequest {
            command: "ls".to_string(),
            path: "/".to_string(),
            user: "bob".to_string(),
        });

        // Set ip addr
        req.extensions_mut()
            .insert::<TcpConnectInfo>(TcpConnectInfo {
                local_addr: Some(SocketAddr::from_str("127.0.0.1:2345").unwrap()),
                remote_addr: Some(SocketAddr::from_str("127.0.0.1:2345").unwrap()),
            });

        // Get result
        let res = firewall.check(req).await;

        // Assertions
        assert!(res.is_ok());
        let res = res.ok();
        assert!(res.is_some());
        let res = res.unwrap();
        let res = res.get_ref();
        assert!(!res.allowed);
    }

    #[tokio::test]
    async fn test_firewall_check_unknown_ip() {
        // Construct service
        let mut firewall: FirewallService = FirewallService::default();
        firewall.set_allowed_ip_addrs(vec![IpAddr::from_str("192.128.12.3").unwrap()]);
        firewall.set_allowed_users(vec!["bob".to_string()]);
        firewall.set_timeout_duration(Duration::from_secs(0));

        firewall.set_eval_cmd("sleep 4".to_string());

        // Create request
        let mut req = Request::new(FirewallRequest {
            command: "ls".to_string(),
            path: "/".to_string(),
            user: "bob".to_string(),
        });

        // Set ip addr
        req.extensions_mut()
            .insert::<TcpConnectInfo>(TcpConnectInfo {
                local_addr: None,
                remote_addr: None,
            });

        // Get result
        let res = firewall.check(req).await;

        // Assertions
        assert!(res.is_err());
        let res = res.err();
        assert!(res.is_some());
        let res = res.unwrap();
        assert_eq!(res.message(), "Ip address not found");
        assert_eq!(res.code(), Status::invalid_argument("").code());
    }
}
