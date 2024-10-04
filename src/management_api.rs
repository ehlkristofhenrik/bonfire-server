use getset::Getters;
use serde::Serialize;
use std::error::Error;

// #[cfg(feature = "github")]
pub use crate::api_providers::github_api::github_api::GithubApi;

pub enum ManagementApis {
    None,
    GithubApi(i32),
}

impl Default for ManagementApis {
    fn default() -> Self {
        Self::None
    }
}

pub trait ManagementApi {
    async fn get_user_profile(&self, user: &str) -> Result<String, Box<dyn std::error::Error>> {
        todo!();
    }
    async fn get_tasks_for_user(
        &self,
        user: &str,
    ) -> Result<Vec<crate::management_api::Task>, Box<dyn std::error::Error>> {
        todo!();
    }
}

#[derive(Serialize, Getters)]
pub struct Task {
    #[getset(get = "pub", set = "pub")]
    task: String,

    #[getset(get = "pub", set = "pub")]
    description: String,
}
