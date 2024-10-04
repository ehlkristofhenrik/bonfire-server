// #[cfg(feature="github")]
pub mod github_api {

    use crate::{
        config::global_config,
        management_api::{ManagementApi, Task},
    };

    use octocrab::Octocrab;
    use serde::Deserialize;

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
        async fn get_user_profile(&self, user: &str) -> Result<String, Box<dyn std::error::Error>> {
            Ok(self
                .inner
                .users(user)
                .profile()
                .await?
                .bio
                .unwrap_or_default())
        }

        async fn get_tasks_for_user(
            &self,
            user: &str,
        ) -> Result<Vec<crate::management_api::Task>, Box<dyn std::error::Error>> {
            Ok(self
                .inner
                .issues(
                    global_config.github_api_config().project_owner.clone(),
                    global_config.github_api_config().project.clone(),
                )
                .list()
                .assignee(user)
                .state(octocrab::params::State::Open)
                .send()
                .await?
                .into_iter()
                .map(|x| Task {
                    task: x.title,
                    description: x.body_text.unwrap_or_default(),
                })
                .collect())
        }
    }
}
