use std::collections::HashMap;

#[cfg(feature = "auditor")]
use akd::{local_auditing::AuditBlobName, SingleAppendOnlyProof, WhatsAppV1Configuration};
#[cfg(feature = "auditor")]
use anyhow::anyhow;
use anyhow::Context as _;
#[cfg(feature = "auditor")]
use protobuf::Message as _;
use serde::{Deserialize, Serialize};
#[cfg(feature = "openapi")]
use utoipa::ToSchema;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct KeyInfo {
    public_key: String,
    not_before: u64,
}

impl KeyInfo {
    pub fn new(public_key: &str, not_before: u64) -> Self {
        Self {
            public_key: public_key.into(),
            not_before,
        }
    }

    pub fn public_key(&self) -> &String {
        &self.public_key
    }

    pub fn not_before(&self) -> u64 {
        self.not_before
    }

    pub fn key_id(&self) -> u8 {
        *hex::decode(&self.public_key)
            .expect("KeyInfo.public_key is always stored as hex")
            .last()
            .expect("fixed size array has a last element")
    }
}

impl From<KeyInfo> for HashMap<String, String> {
    fn from(val: KeyInfo) -> Self {
        let mut map = HashMap::new();
        // Clone the String for key 'public_key'
        map.insert("public_key".to_string(), val.public_key.clone());
        // Convert u64 to String for key 'not_before'
        map.insert("not_before".to_string(), val.not_before.to_string());
        map
    }
}

impl TryFrom<HashMap<String, String>> for KeyInfo {
    type Error = anyhow::Error;

    fn try_from(value: HashMap<String, String>) -> Result<Self, Self::Error> {
        Ok(Self {
            public_key: value
                .get("public_key")
                .context("getting KeyInfo public key")?
                .clone(),
            not_before: value
                .get("not_before")
                .context("getting KeyInfo not_before")?
                .parse()?,
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct Configuration {
    keys: Vec<KeyInfo>,
    logs: Vec<String>,
}

impl Configuration {
    pub fn new(keys: &[KeyInfo], logs: &[String]) -> Self {
        Self {
            keys: keys.to_vec(),
            logs: logs.to_vec(),
        }
    }

    pub fn keys(&self) -> &Vec<KeyInfo> {
        &self.keys
    }

    pub fn logs(&self) -> &Vec<String> {
        &self.logs
    }
}

#[cfg(feature = "auditor")]
pub async fn verify_raw_proof(blob: &AuditBlobName, raw_proof: &[u8]) -> anyhow::Result<()> {
    let proto = akd::proto::specs::types::SingleAppendOnlyProof::parse_from_bytes(raw_proof)
        .context("unable to parse proof bytes")?;

    let proof = SingleAppendOnlyProof::try_from(&proto)
        .map_err(|e| anyhow::anyhow!(e.to_string()))
        .context("converting parsed protobuf proof to `SingleAppendOnlyProof`")?;

    akd::auditor::verify_consecutive_append_only::<WhatsAppV1Configuration>(
        &proof, blob.previous_hash, blob.current_hash, blob.epoch,
    )
    .await
    .with_context(|| {
        format!(
            "verifying raw proof: {blob}",
            blob = blob.to_string()
        )
    }).map_err(|e| anyhow!(e))
}