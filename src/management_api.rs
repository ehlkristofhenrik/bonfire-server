use getset::Getters;
use serde::Serialize;

#[cfg(feature = "github")]
use crate::management_api_providers::github_api::github_api::GithubApi;

// Enum of management apis
// This is used to avoid dyn traits for object safety
pub enum ManagementApis {
    None,
    #[cfg(feature = "github")]
    GithubApi(GithubApi),
}

impl ManagementApis {
    // Get user profile, should contain role in the organization
    pub async fn get_user_profile(&self, _user: &str) -> Result<String, ()> {
        match self {
            Self::None => Ok("".to_string()),
            #[cfg(feature = "github")]
            Self::GithubApi(github) => github.get_user_profile(_user).await,
        }
    }

    // Get list of tasks for user
    pub async fn get_tasks_for_user(&self, _user: &str) -> Result<Vec<Task>, ()> {
        match self {
            Self::None => Ok(vec![]),
            #[cfg(feature = "github")]
            Self::GithubApi(github) => github.get_tasks_for_user(_user).await,
        }
    }
}

// Default implementation of ManagementApis
impl Default for ManagementApis {
    fn default() -> Self {
        Self::None
    }
}

pub trait ManagementApi {
    // Get user profile, should describe their role in the organization
    async fn get_user_profile(&self, _user: &str) -> Result<String, ()> {
        todo!();
    }

    // Get list of tasks assigned for user
    async fn get_tasks_for_user(
        &self,
        _user: &str,
    ) -> Result<Vec<crate::management_api::Task>, ()> {
        todo!();
    }
}

#[derive(Serialize, Getters, Clone)]
pub struct Task {
    // Task title
    pub task: String,
    // Description for task
    pub description: String,
}
