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
#[cfg(feature = "openapi")]
use utoipa::ToSchema;

pub use uuid::Uuid;

pub mod crypto;
pub mod namespaces;
pub mod proto;

const SIGNATURE_VERSIONS: [SignatureVersion; 2] = [
    SignatureVersion::ProtobufEd25519,
    SignatureVersion::BincodeEd25519,
];

#[derive(Error, Debug)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub enum PlexiError {
    #[error("invalid parameter `{0}`")]
    BadParameter(String),
    #[error("missing parameter `{0}`")]
    MissingParameter(String),
    #[error("cannot serialize message")]
    Serialization,
    #[error("Root is not valid")]
    InvalidRoot,
}

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
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
        let value: u32 = (*self).into();
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

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Encode, Decode)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
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

impl From<Epoch> for u64 {
    fn from(val: Epoch) -> Self {
        val.0
    }
}

impl From<u64> for Epoch {
    fn from(val: u64) -> Self {
        Epoch(val)
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
#[cfg_attr(feature = "openapi", derive(ToSchema))]
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
            version: *version,
            namespace,
            timestamp,
            epoch: *epoch,
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
            version: (*self.version()).into(),
            namespace: self.namespace().to_string(),
            timestamp: self.timestamp(),
            epoch: proto::types::Epoch {
                inner: self.epoch().into(),
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
#[cfg_attr(feature = "openapi", derive(ToSchema))]
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

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
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
        self.epoch
    }

    pub fn digest(&self) -> Vec<u8> {
        self.digest.clone()
    }
}

impl fmt::Debug for SignatureRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignatureRequest")
            .field("epoch", &self.epoch)
            .field("digest", &hex::encode(&self.digest))
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct SignatureResponse {
    version: SignatureVersion,
    namespace: String,
    timestamp: u64,
    epoch: Epoch,
    #[serde(with = "hex::serde")]
    digest: Vec<u8>,
    #[serde(with = "hex::serde")]
    signature: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_id: Option<u8>,
}

impl fmt::Debug for SignatureResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignatureResponse")
            .field("version", &self.version)
            .field("namespace", &self.namespace)
            .field("timestamp", &self.timestamp)
            .field("epoch", &self.epoch)
            .field("digest", &hex::encode(&self.digest))
            .field("signature", &hex::encode(&self.signature))
            .field("key_id", &self.key_id)
            .finish()
    }
}

impl SignatureResponse {
    pub fn new(
        version: &SignatureVersion,
        namespace: String,
        timestamp: u64,
        epoch: &Epoch,
        digest: Vec<u8>,
        signature: Vec<u8>,
        key_id: Option<u8>,
    ) -> Self {
        Self {
            version: *version,
            namespace,
            timestamp,
            epoch: *epoch,
            digest,
            signature,
            key_id,
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
        self.signature
            .as_slice()
            .try_into()
            .expect("signature bytes have a known length")
    }

    pub fn key_id(&self) -> Option<u8> {
        self.key_id
    }
}

// A report request is a signature reponse, except the signature does not come from the auditor (thought to be offline) but from the log provider
pub type Report = SignatureResponse;

impl From<Report> for HashMap<String, String> {
    fn from(val: Report) -> Self {
        let mut map = HashMap::new();
        let version: u32 = (*val.version()).into();
        map.insert("version".to_string(), version.to_string());
        map.insert("namespace".to_string(), val.namespace().to_string());
        map.insert("timestamp".to_string(), val.timestamp.to_string());
        map.insert("epoch".to_string(), val.epoch.to_string());
        map.insert("digest".to_string(), hex::encode(val.digest));
        map.insert("signature".to_string(), hex::encode(val.signature));
        if let Some(key_id) = val.key_id {
            map.insert("key_id".to_string(), key_id.to_string());
        }
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
            key_id: value
                .get("key_id")
                .map(|id| id.parse())
                .transpose()
                .map_err(|_| PlexiError::BadParameter("key_id".to_string()))?,
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

#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct LastVerifiedEpoch {
    job_id: Uuid,
    epoch: Epoch,
    #[serde(with = "hex::serde")]
    start_hash: Vec<u8>,
    #[serde(with = "hex::serde")]
    end_hash: Vec<u8>,
    timestamp: u64,
}

impl fmt::Debug for LastVerifiedEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LastVerifiedEpoch")
            .field("job_id", &self.job_id)
            .field("epoch", &self.epoch)
            .field("start_hash", &hex::encode(&self.start_hash))
            .field("end_hash", &hex::encode(&self.end_hash))
            .field("timestamp", &self.timestamp)
            .finish()
    }
}

impl LastVerifiedEpoch {
    pub fn new(
        job_id: Uuid,
        epoch: Epoch,
        start_hash: Vec<u8>,
        end_hash: Vec<u8>,
        timestamp: u64,
    ) -> Self {
        Self {
            job_id,
            epoch,
            start_hash,
            end_hash,
            timestamp,
        }
    }

    pub fn job_id(&self) -> Uuid {
        self.job_id
    }

    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub fn start_hash(&self) -> &[u8] {
        &self.start_hash
    }

    pub fn end_hash(&self) -> &[u8] {
        &self.end_hash
    }

    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
}

#[cfg(test)]
mod tests {
    use crypto::ed25519_public_key_to_key_id;
    use ed25519_dalek::{ed25519::signature::SignerMut, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};

    use super::*;

    #[test]
    fn test_vector() {
        const TEST_VECTORS: &str = std::include_str!("../tests/test-vectors.json");

        #[derive(Deserialize, Debug, Clone)]
        pub struct TestVector {
            #[serde(with = "hex::serde")]
            signing_key: [u8; SECRET_KEY_LENGTH],
            #[serde(with = "hex::serde")]
            verifying_key: [u8; PUBLIC_KEY_LENGTH],
            key_id: u8,
            namespace: String,
            timestamp: u64,
            epoch: Epoch,
            #[serde(with = "hex::serde")]
            digest: Vec<u8>,
            #[serde(with = "hex::serde")]
            signature: [u8; SIGNATURE_LENGTH],
            signature_version: SignatureVersion,
        }

        let test_vectors: Vec<TestVector> = serde_json::from_str(TEST_VECTORS).unwrap();
        for tv in test_vectors {
            let mut signing_key = ed25519_dalek::SigningKey::from_bytes(&tv.signing_key);
            let verifying_key = signing_key.verifying_key();
            assert_eq!(verifying_key.to_bytes(), tv.verifying_key);

            let key_id = ed25519_public_key_to_key_id(&verifying_key.to_bytes());
            assert_eq!(key_id, tv.key_id);

            let message = SignatureMessage::new(
                &tv.signature_version,
                tv.namespace,
                tv.timestamp,
                &tv.epoch,
                tv.digest,
            )
            .unwrap();

            let signature = signing_key.sign(&message.to_vec().unwrap());
            assert_eq!(signature.to_bytes(), tv.signature);

            assert!(verifying_key
                .verify_strict(&message.to_vec().unwrap(), &signature)
                .is_ok());
        }
    }
}
