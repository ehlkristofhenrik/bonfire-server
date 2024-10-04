// #[cfg(feature="github")]
pub mod github_api {
    
    use crate::management_api::ManagementApi;

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
            todo!()
        }

        async fn get_tasks_for_user(
            &self,
            user: &str,
        ) -> Result<Vec<crate::management_api::Task>, Box<dyn std::error::Error>> {
            todo!()
        }
    }
}
