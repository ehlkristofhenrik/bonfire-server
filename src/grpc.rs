mod proto {
    tonic::include_proto!("secu_score");
}

#[cfg(not(test))]
use crate::llama::query_secu_score;

#[cfg(test)]
use crate::llama::*;

use crate::{
    api_providers::github_api::github_api::GithubApi,
    management_api::{ManagementApi, ManagementApis},
};

use getset::Setters;
use proto::firewall_server::Firewall;
pub use proto::firewall_server::FirewallServer;
use proto::{FirewallReply, FirewallRequest};
use ring::constant_time::verify_slices_are_equal;
use std::net::IpAddr;
pub use tonic::transport::Server;
use tonic::{Response, Status};

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
            return Err(Status::invalid_argument("Ip address not found"));
        };

        // Get request body
        let request: &FirewallRequest = request.get_ref();

        let user_str: &str = request.user.as_str();

        // Query user profile
        let (issues, role) = match &self.management_api {
            ManagementApis::None => (vec![], "".to_string()),
            // #[cfg(feature = "github")]
            ManagementApis::GithubApi(api) => (
                api.get_tasks_for_user(user_str).await.unwrap_or_default(),
                api.get_user_profile(user_str).await.unwrap_or_default(),
            ),
            // #[cfg(test)]
            ManagementApis::TestApi(api) => (
                api.get_tasks_for_user(user_str).await.unwrap_or_default(),
                api.get_user_profile(user_str).await.unwrap_or_default(),
            ),
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
            return Err(Status::permission_denied("You shall not pass"));
        };

        #[cfg(test)]
        let Ok(score) = Result::<SecuScore, ()>::Ok(SecuScore::default()) else {
            todo!();
        };

        // TODO! Compute the score

        Ok(Response::new(FirewallReply { allowed: true }))
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
}
