use crate::management_api::Task;
use getset::{CopyGetters, Getters};
use serde::Deserialize;
use std::error::Error;

#[derive(Debug, Default, Deserialize, Getters, CopyGetters)]
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

#[cfg(feature = "llamafile")]
use crate::inference_api_providers::llamafile::LlamaFile;

#[derive(Clone)]
pub enum InferenceApis {
    None,
    #[cfg(feature = "llamafile")]
    LlamaFile(LlamaFile),
}

impl Default for InferenceApis {
    fn default() -> Self {
        Self::None
    }
}

impl InferenceApis {
    pub async fn get_secu_score(
        self,
        command: String,
        user: String,
        path: String,
        task: Vec<Task>,
        role: String,
    ) -> Result<SecuScore, Box<dyn Error>> {
        match self {
            Self::None => Ok(SecuScore::default()),
            #[cfg(feature = "llamafile")]
            Self::LlamaFile(llama) => llama.get_secu_score(command, user, path, task, role).await,
        }
    }
}

pub trait InferenceApi {
    async fn get_secu_score(
        self,
        command: String,
        user: String,
        path: String,
        task: Vec<Task>,
        role: String,
    ) -> Result<SecuScore, Box<dyn Error>>;
}
