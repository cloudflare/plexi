use std::collections::HashMap;

use anyhow::{anyhow, Result};
use bincode::{Decode, Encode};
use ed25519_dalek::SIGNATURE_LENGTH;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode)]
pub struct SignatureMessage {
    timestamp: u64,
    epoch: u64,
    #[serde(with = "hex::serde")]
    digest: Vec<u8>,
}

impl SignatureMessage {
    pub fn new(timestamp: u64, epoch: u64, digest: Vec<u8>) -> Self {
        Self {
            timestamp,
            epoch,
            digest,
        }
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn digest(&self) -> Vec<u8> {
        self.digest.clone()
    }

    pub fn to_vec(&self) -> Result<Vec<u8>> {
        bincode::encode_to_vec(self, bincode::config::legacy())
            .map_err(|_e| anyhow!("cannot serialize message"))
    }
}

impl From<SignatureResponse> for SignatureMessage {
    fn from(val: SignatureResponse) -> Self {
        Self {
            timestamp: val.timestamp,
            epoch: val.epoch,
            digest: val.digest,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureMetadata {
    digest: String,
}

impl From<SignatureMetadata> for HashMap<String, String> {
    fn from(val: SignatureMetadata) -> Self {
        let mut map = HashMap::new();
        // Convert u64 to String for key 'a'
        map.insert("digest".to_string(), val.digest.clone());
        map
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureRequest {
    epoch: u64,
    #[serde(with = "hex::serde")]
    digest: Vec<u8>,
    // TODO: previous digest?
}

impl SignatureRequest {
    pub fn new(epoch: u64, digest: Vec<u8>) -> Self {
        Self { epoch, digest }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn digest(&self) -> Vec<u8> {
        self.digest.clone()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureResponse {
    timestamp: u64,
    epoch: u64,
    #[serde(with = "hex::serde")]
    digest: Vec<u8>,
    #[serde(with = "hex::serde")]
    signature: Vec<u8>,
}

impl SignatureResponse {
    pub fn new(timestamp: u64, epoch: u64, digest: Vec<u8>, signature: Vec<u8>) -> Self {
        Self {
            timestamp,
            epoch,
            digest,
            signature,
        }
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn digest(&self) -> Vec<u8> {
        self.digest.clone()
    }

    pub fn signature(&self) -> [u8; SIGNATURE_LENGTH] {
        self.signature.as_slice().try_into().unwrap()
    }
}

// A report request is a signature reponse, except the signature does not come from the auditor (thought to be offline) but from the log provider
pub type Report = SignatureResponse;

impl From<Report> for HashMap<String, String> {
    fn from(val: Report) -> Self {
        let mut map = HashMap::new();
        map.insert("timestamp".to_string(), val.timestamp.to_string());
        map.insert("epoch".to_string(), val.epoch.to_string());
        map.insert("digest".to_string(), hex::encode(val.digest));
        map.insert("signature".to_string(), hex::encode(val.signature));
        map
    }
}

impl TryFrom<HashMap<String, String>> for Report {
    type Error = anyhow::Error;

    fn try_from(value: HashMap<String, String>) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            timestamp: value
                .get("timestamp")
                .ok_or_else(|| anyhow::anyhow!("Missing timestamp"))?
                .parse()?,
            epoch: value
                .get("epoch")
                .ok_or_else(|| anyhow::anyhow!("Missing epoch"))?
                .parse()?,
            digest: hex::decode(
                value
                    .get("digest")
                    .ok_or_else(|| anyhow::anyhow!("Missing digest"))?,
            )?,
            signature: hex::decode(
                value
                    .get("signature")
                    .ok_or_else(|| anyhow::anyhow!("Missing signature"))?,
            )?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReportResponse {
    id: Uuid,
    report: Report,
}

impl ReportResponse {
    pub fn new(id: Uuid, report: Report) -> Self {
        Self { id, report }
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn report(&self) -> Report {
        self.report.clone()
    }
}
