use std::{
    collections::HashMap,
    fmt::{self, Display},
    ops::{Add, Sub},
    str::FromStr,
};

use bincode::{Decode, Encode};
use ed25519_dalek::SIGNATURE_LENGTH;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum PlexiError {
    #[error("invalid parameter `{0}`")]
    BadParameter(String),
    #[error("missing parameter `{0}`")]
    MissingParameter(String),
    #[error("cannot serialize message")]
    Serialization,
}

#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode)]
pub struct Epoch(u64);

pub const FIRST_EPOCH: Epoch = Epoch(1);

impl Epoch {
    pub fn is_first(&self) -> bool {
        self.0 == FIRST_EPOCH.0
    }
}

impl From<Epoch> for u64 {
    fn from(val: Epoch) -> Self {
        val.0
    }
}

impl fmt::Display for Epoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Epoch {
    type Err = PlexiError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        s.parse::<u64>()
            .map(Epoch)
            .map_err(|_| PlexiError::BadParameter("epoch".to_string()))
    }
}

impl PartialEq<u64> for Epoch {
    fn eq(&self, other: &u64) -> bool {
        self.0 == *other
    }
}

impl PartialEq<Epoch> for u64 {
    fn eq(&self, other: &Epoch) -> bool {
        *self == other.0
    }
}

impl Add<u64> for Epoch {
    type Output = Epoch;

    fn add(self, rhs: u64) -> Epoch {
        Epoch(self.0 + rhs)
    }
}

impl Sub<u64> for Epoch {
    type Output = Epoch;

    fn sub(self, rhs: u64) -> Epoch {
        Epoch(self.0 - rhs)
    }
}

impl Add<Epoch> for Epoch {
    type Output = Epoch;

    fn add(self, rhs: Epoch) -> Epoch {
        Epoch(self.0 + rhs.0)
    }
}

impl Sub<Epoch> for Epoch {
    type Output = Epoch;

    fn sub(self, rhs: Epoch) -> Epoch {
        Epoch(self.0 - rhs.0)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode)]
pub struct SignatureMessage {
    namespace: String,
    timestamp: u64,
    epoch: Epoch,
    #[serde(with = "hex::serde")]
    digest: Vec<u8>,
    // TODO: consider adding a version
}

impl SignatureMessage {
    pub fn new(namespace: String, timestamp: u64, epoch: &Epoch, digest: Vec<u8>) -> Self {
        Self {
            namespace,
            timestamp,
            epoch: epoch.clone(),
            digest,
        }
    }

    pub fn namespace(&self) -> String {
        self.namespace.clone()
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub fn epoch(&self) -> Epoch {
        self.epoch.clone()
    }

    pub fn digest(&self) -> Vec<u8> {
        self.digest.clone()
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, PlexiError> {
        bincode::encode_to_vec(self, bincode::config::legacy())
            .map_err(|_e| PlexiError::Serialization)
    }
}

impl From<SignatureResponse> for SignatureMessage {
    fn from(val: SignatureResponse) -> Self {
        Self {
            namespace: val.namespace,
            timestamp: val.timestamp,
            epoch: val.epoch,
            digest: val.digest,
        }
    }
}

impl Display for SignatureMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}",
            self.epoch,
            hex::encode(self.digest.clone())
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureMetadata {
    digest: String,
}

impl From<SignatureMetadata> for HashMap<String, String> {
    fn from(val: SignatureMetadata) -> Self {
        let mut map = HashMap::new();
        map.insert("digest".to_string(), val.digest.clone());
        map
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureRequest {
    epoch: Epoch,
    #[serde(with = "hex::serde")]
    digest: Vec<u8>,
    // TODO: previous digest?
}

impl SignatureRequest {
    pub fn new(epoch: Epoch, digest: Vec<u8>) -> Self {
        Self { epoch, digest }
    }

    pub fn epoch(&self) -> Epoch {
        self.epoch.clone()
    }

    pub fn digest(&self) -> Vec<u8> {
        self.digest.clone()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureResponse {
    namespace: String,
    timestamp: u64,
    epoch: Epoch,
    #[serde(with = "hex::serde")]
    digest: Vec<u8>,
    #[serde(with = "hex::serde")]
    signature: Vec<u8>,
}

impl SignatureResponse {
    pub fn new(namespace: String, timestamp: u64, epoch: &Epoch, digest: Vec<u8>, signature: Vec<u8>) -> Self {
        Self {
            namespace,
            timestamp,
            epoch: epoch.clone(),
            digest,
            signature,
        }
    }

    pub fn namespace(&self) -> String {
        self.namespace.clone()
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub fn epoch(&self) -> Epoch {
        self.epoch.clone()
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
        map.insert("namespace".to_string(), val.namespace());
        map.insert("timestamp".to_string(), val.timestamp.to_string());
        map.insert("epoch".to_string(), val.epoch.to_string());
        map.insert("digest".to_string(), hex::encode(val.digest));
        map.insert("signature".to_string(), hex::encode(val.signature));
        map
    }
}

impl TryFrom<HashMap<String, String>> for Report {
    type Error = PlexiError;

    fn try_from(value: HashMap<String, String>) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            namespace: value
                .get("namespace")
                .ok_or_else(|| PlexiError::MissingParameter("namespace".to_string()))?
                .clone(),
            timestamp: value
                .get("timestamp")
                .ok_or_else(|| PlexiError::MissingParameter("timestamp".to_string()))?
                .parse()
                .map_err(|_| PlexiError::BadParameter("timestamp".to_string()))?,
            epoch: value
                .get("epoch")
                .ok_or_else(|| PlexiError::MissingParameter("epoch".to_string()))?
                .parse()?,
            digest: hex::decode(
                value
                    .get("digest")
                    .ok_or_else(|| PlexiError::MissingParameter("digest".to_string()))?,
            )
            .map_err(|_| PlexiError::BadParameter("digest".to_string()))?,
            signature: hex::decode(
                value
                    .get("signature")
                    .ok_or_else(|| PlexiError::MissingParameter("signature".to_string()))?,
            )
            .map_err(|_| PlexiError::BadParameter("signature".to_string()))?,
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
