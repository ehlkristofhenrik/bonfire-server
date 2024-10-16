#[cfg(feature = "github")]
pub mod github_api {

    use crate::{
        config::global_config,
        management_api::{ManagementApi, Task},
    };

    use octocrab::Octocrab;
    use serde::Deserialize;
    use tracing::error;

    use std::sync::Arc;

    #[derive(Default, Clone)]
    pub struct GithubApi {
        inner: Arc<Octocrab>,
    }

    #[derive(Deserialize, Default)]
    pub struct GithubApiConfig {
        project_owner: String,
        project: String,
    }

    impl GithubApi {
        pub fn new() -> Self {
            Self {
                inner: octocrab::instance(),
            }
        }
    }

    impl ManagementApi for GithubApi {
        async fn get_user_profile(&self, user: &str) -> Result<String, ()> {
            let res = self.inner.users(user).profile().await;
            if let Ok(res) = res {
                Ok(res.bio.unwrap_or_default())
            } else {
                error!("Failed to query user profile");
                Err(())
            }
        }

        async fn get_tasks_for_user(
            &self,
            user: &str,
        ) -> Result<Vec<crate::management_api::Task>, ()> {
            let res = self
                .inner
                .issues(
                    global_config.github_api_config().project_owner.clone(),
                    global_config.github_api_config().project.clone(),
                )
                .list()
                .assignee(user)
                .state(octocrab::params::State::Open)
                .send()
                .await;
            if let Ok(res) = res {
                Ok(res
                    .into_iter()
                    .map(|x| Task {
                        task: x.title,
                        description: x.body_text.unwrap_or_default(),
                    })
                    .collect())
            } else {
                Err(())
            }
        }
    }
}
