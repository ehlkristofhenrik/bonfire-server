use crate::management_api::Task;
use getset::{CopyGetters, Getters};
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::error::Error;

#[derive(Deserialize, Debug)]
pub struct Score {
    content: String,
}

#[derive(Default, Deserialize, Getters, CopyGetters)]
pub struct SecuScore {
    // Instructs the model to generate a step by step explaination
    #[allow(unused)]
    overall_reasoning: String,

    // Instructs the model to think about user intentions
    #[allow(unused)]
    malignity_reasoning: String,

    // Represents the maliciousness of the users intentions
    #[getset(get = "pub")]
    malignity_score: u8,

    // Instructs the model to think about action seriousness
    #[allow(unused)]
    severity_reasoning: String,

    // Represents the seriousness of the command
    #[getset(get = "pub")]
    severity_score: u8,

    // Instructs the model to think about action usefulness
    #[allow(unused)]
    utility_reasoning: String,

    // Represents the usefulness of the command
    #[getset(get = "pub")]
    utility_score: u8,

    // Instructs the model to think about expectations based on role
    #[allow(unused)]
    expectance_reasoning: String,

    // Represents the expectedness of the command
    #[getset(get = "pub")]
    expectance_score: u8,
}

// Queries LLM for secu score
pub async fn query_secu_score(
    url: String,
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
            include_str!("../static/grammar.gbnf").to_string(),
        ),
    ]);

    // Setup client
    let resp: Score = Client::new()
        .post(url)
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
