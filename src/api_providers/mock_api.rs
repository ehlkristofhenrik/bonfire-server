pub mod mock_api {
    use crate::management_api::{ManagementApi, Task};
    use std::error::Error;

    pub struct MockApi {
        tasks_result: Vec<Task>,
        profile_result: String,
    }

    impl ManagementApi for MockApi {
        async fn get_user_profile(&self, user: &str) -> Result<String, Box<dyn Error>> {
            Ok(self.profile_result.clone())
        }

        async fn get_tasks_for_user(
            &self,
            user: &str,
        ) -> Result<Vec<crate::management_api::Task>, Box<dyn Error>> {
            Ok(self.tasks_result.to_vec())
        }
    }
}
