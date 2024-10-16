use crate::management_api::Task;
use getset::{CopyGetters, Getters};
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::error::Error;
use crate::inference_api::{InferenceApi, SecuScore};

#[derive(Deserialize, Debug)]
struct Score {
    #[allow(unused)]
    content: String,
}

#[derive(Clone)]
pub struct LlamaFile {
    url: String
}

impl LlamaFile {
    pub fn new( url: String ) -> Self {
        Self {
            url
        }
    }
}

impl InferenceApi for LlamaFile {
    // Queries LLM for secu score
    async fn get_secu_score(
        self,
        command: String,
        user: String,
        path: String,
        task: Vec<Task>,
        role: String,
    ) -> Result<SecuScore, Box<dyn Error>> {
        // Setup POST json
        let map = HashMap::from([
            (
                "prompt",
                json!({
                    "task": task,
                    "command": command,
                    "user": user,
                    "role": role,
                    "cwd": path
                })
                .to_string(),
            ),
            (
                "grammar",
                include_str!("../../static/grammar.gbnf").to_string(),
            ),
        ]);

        // Setup client
        let resp: Score = Client::new()
            .post(self.url)
            .header("Authorization", "Bearer no-key")
            .header("Content-Type", "application/json")
            .json(&map)
            .send()
            .await?
            .json()
            .await?;

        // Remove trailing EOT & EOM tokens
        let Some(json_end) = resp.content.rfind("}") else {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Json invalid",
            )));
        };
        let content: String = resp.content[..=json_end].to_string();

        Ok(serde_json::from_str(&content)?)
    }

}