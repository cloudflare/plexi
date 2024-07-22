use std::{
    collections::HashMap,
    fmt::{self, Display},
    num::ParseIntError,
    ops::{Add, Sub},
    str::FromStr,
};

use bincode::{BorrowDecode, Decode, Encode};
use ed25519_dalek::SIGNATURE_LENGTH;
use prost::Message;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub mod proto;

const SIGNATURE_VERSIONS: [SignatureVersion; 2] = [
    SignatureVersion::ProtobufEd25519,
    SignatureVersion::BincodeEd25519,
];

#[derive(Error, Debug)]
pub enum PlexiError {
    #[error("invalid parameter `{0}`")]
    BadParameter(String),
    #[error("missing parameter `{0}`")]
    MissingParameter(String),
    #[error("cannot serialize message")]
    Serialization,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(into = "u32")]
#[serde(from = "u32")]
#[repr(u32)]
pub enum SignatureVersion {
    ProtobufEd25519 = 0x0001,
    BincodeEd25519 = 0x0002,
    Unknown(u32),
}

impl From<SignatureVersion> for u32 {
    fn from(val: SignatureVersion) -> Self {
        match val {
            SignatureVersion::ProtobufEd25519 => 0x0001,
            SignatureVersion::BincodeEd25519 => 0x0002,
            SignatureVersion::Unknown(u) => u,
        }
    }
}

impl From<u32> for SignatureVersion {
    fn from(u: u32) -> Self {
        match u {
            0x0001 => Self::ProtobufEd25519,
            0x0002 => Self::BincodeEd25519,
            _ => Self::Unknown(u),
        }
    }
}

impl FromStr for SignatureVersion {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let u: u32 = s.parse()?;
        Ok(u.into())
    }
}

impl fmt::Display for SignatureVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::ProtobufEd25519 => "0x0001",
            Self::BincodeEd25519 => "0x0002",
            Self::Unknown(_u) => "unknown",
        };
        write!(f, "{}", s)
    }
}

impl Encode for SignatureVersion {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        let value: u32 = self.clone().into();
        bincode::Encode::encode(&value, encoder)
    }
}

impl Decode for SignatureVersion {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let value: u32 = bincode::Decode::decode(decoder)?;
        Ok(value.into())
    }
}

impl<'de> BorrowDecode<'de> for SignatureVersion {
    fn borrow_decode<B: bincode::de::BorrowDecoder<'de>>(
        buffer: &mut B,
    ) -> Result<Self, bincode::error::DecodeError> {
        let value = u32::borrow_decode(buffer)?;
        Ok(value.into())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Encode, Decode)]
pub struct Epoch(u64);

pub const FIRST_EPOCH: Epoch = Epoch(1);

impl Epoch {
    pub fn is_first(&self) -> bool {
        self.0 == FIRST_EPOCH.0
    }
}

impl From<&Epoch> for u64 {
    fn from(val: &Epoch) -> Self {
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
    version: SignatureVersion,
    namespace: String,
    timestamp: u64,
    epoch: Epoch,
    #[serde(with = "hex::serde")]
    digest: Vec<u8>,
    // TODO: consider adding a version
}

impl SignatureMessage {
    pub fn new(
        version: &SignatureVersion,
        namespace: String,
        timestamp: u64,
        epoch: &Epoch,
        digest: Vec<u8>,
    ) -> Result<Self, PlexiError> {
        if !SIGNATURE_VERSIONS.contains(version) {
            return Err(PlexiError::BadParameter("version".to_string()));
        }
        Ok(Self {
            version: version.clone(),
            namespace,
            timestamp,
            epoch: epoch.clone(),
            digest,
        })
    }

    pub fn version(&self) -> &SignatureVersion {
        &self.version
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub fn epoch(&self) -> &Epoch {
        &self.epoch
    }

    pub fn digest(&self) -> Vec<u8> {
        self.digest.clone()
    }

    fn to_vec_bincode(&self) -> Result<Vec<u8>, PlexiError> {
        bincode::encode_to_vec(self, bincode::config::legacy())
            .map_err(|_e| PlexiError::Serialization)
    }

    fn to_vec_proto(&self) -> Result<Vec<u8>, PlexiError> {
        let message = proto::types::SignatureMessage {
            version: self.version().clone().into(),
            namespace: self.namespace().to_string(),
            timestamp: self.timestamp(),
            epoch: proto::types::Epoch {
                inner: Some(self.epoch().into()),
            },
            digest: self.digest().clone(),
        };

        Ok(message.encode_to_vec())
    }

    pub fn to_vec(&self) -> Result<Vec<u8>, PlexiError> {
        match self.version {
            SignatureVersion::ProtobufEd25519 => self.to_vec_proto(),
            SignatureVersion::BincodeEd25519 => self.to_vec_bincode(),
            _ => Err(PlexiError::Serialization),
        }
    }
}

impl From<SignatureResponse> for SignatureMessage {
    fn from(val: SignatureResponse) -> Self {
        Self {
            version: val.version,
            namespace: val.namespace,
            timestamp: val.timestamp,
            epoch: val.epoch,
            digest: val.digest,
        }
    }
}

impl Display for SignatureMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.epoch, hex::encode(self.digest.clone()))
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
    version: SignatureVersion,
    namespace: String,
    timestamp: u64,
    epoch: Epoch,
    #[serde(with = "hex::serde")]
    digest: Vec<u8>,
    #[serde(with = "hex::serde")]
    signature: Vec<u8>,
}

impl SignatureResponse {
    pub fn new(
        version: &SignatureVersion,
        namespace: String,
        timestamp: u64,
        epoch: &Epoch,
        digest: Vec<u8>,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            version: version.clone(),
            namespace,
            timestamp,
            epoch: epoch.clone(),
            digest,
            signature,
        }
    }

    pub fn version(&self) -> &SignatureVersion {
        &self.version
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    pub fn epoch(&self) -> &Epoch {
        &self.epoch
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
        let version: u32 = val.version().clone().into();
        map.insert("version".to_string(), version.to_string());
        map.insert("namespace".to_string(), val.namespace().to_string());
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
            version: value
                .get("version")
                .ok_or_else(|| PlexiError::MissingParameter("version".to_string()))?
                .parse()
                .map_err(|_| PlexiError::BadParameter("version".to_string()))?,
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
