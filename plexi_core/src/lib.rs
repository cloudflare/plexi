use std::{
    collections::HashMap,
    fmt::{self, Display},
    num::ParseIntError,
    ops::{Add, Sub},
    str::FromStr,
};

use anyhow::anyhow;
#[cfg(feature = "bincode")]
use bincode::{BorrowDecode, Decode, Encode};
use ed25519_dalek::SIGNATURE_LENGTH;
use prost::Message;
use serde::{de, Deserializer, Serializer};
use serde::{Deserialize, Serialize};
use thiserror::Error;
#[cfg(feature = "openapi")]
use utoipa::ToSchema;

pub use uuid::Uuid;

pub mod auditor;
#[cfg(feature = "client")]
pub mod client;
pub mod crypto;
pub mod namespaces;
pub mod proto;

const SIGNATURE_VERSIONS: [Ciphersuite; 2] =
    [Ciphersuite::ProtobufEd25519, Ciphersuite::BincodeEd25519];

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
pub enum Ciphersuite {
    ProtobufEd25519 = 0x0001,
    BincodeEd25519 = 0x0002,
    Unknown(u32),
}

impl From<Ciphersuite> for u32 {
    fn from(val: Ciphersuite) -> Self {
        match val {
            Ciphersuite::ProtobufEd25519 => 0x0001,
            Ciphersuite::BincodeEd25519 => 0x0002,
            Ciphersuite::Unknown(u) => u,
        }
    }
}

impl From<u32> for Ciphersuite {
    fn from(u: u32) -> Self {
        match u {
            0x0001 => Self::ProtobufEd25519,
            0x0002 => Self::BincodeEd25519,
            _ => Self::Unknown(u),
        }
    }
}

impl FromStr for Ciphersuite {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let u: u32 = s.parse()?;
        Ok(u.into())
    }
}

impl fmt::Display for Ciphersuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::ProtobufEd25519 => "0x0001",
            Self::BincodeEd25519 => "0x0002",
            Self::Unknown(_u) => "unknown",
        };
        write!(f, "{s}")
    }
}

#[cfg(feature = "bincode")]
impl Encode for Ciphersuite {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> Result<(), bincode::error::EncodeError> {
        let value: u32 = (*self).into();
        bincode::Encode::encode(&value, encoder)
    }
}

#[cfg(feature = "bincode")]
impl<Context> Decode<Context> for Ciphersuite {
    fn decode<D: bincode::de::Decoder<Context = Context>>(
        decoder: &mut D,
    ) -> Result<Self, bincode::error::DecodeError> {
        let value: u32 = bincode::Decode::decode(decoder)?;
        Ok(value.into())
    }
}

#[cfg(feature = "bincode")]
impl<'de, Context> BorrowDecode<'de, Context> for Ciphersuite {
    fn borrow_decode<B: bincode::de::BorrowDecoder<'de, Context = Context>>(
        buffer: &mut B,
    ) -> Result<Self, bincode::error::DecodeError> {
        let value = u32::borrow_decode(buffer)?;
        Ok(value.into())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct Epoch(u64);

pub const FIRST_EPOCH: Epoch = Epoch(1);

impl Epoch {
    pub fn is_first(&self) -> bool {
        self.0 == FIRST_EPOCH.0
    }

    pub fn as_root_epoch(&self, digest: &str) -> String {
        format!("{}/{}", self.0, digest)
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

impl PartialEq<Epoch> for Epoch {
    fn eq(&self, other: &Epoch) -> bool {
        *self == other.0
    }
}

impl PartialOrd<Epoch> for Epoch {
    fn partial_cmp(&self, other: &Epoch) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct SignatureMessage {
    ciphersuite: Ciphersuite,
    namespace: String,
    timestamp: u64,
    epoch: Epoch,
    #[serde(with = "hex::serde")]
    digest: Vec<u8>,
}

impl SignatureMessage {
    pub fn new(
        ciphersuite: &Ciphersuite,
        namespace: String,
        timestamp: u64,
        epoch: &Epoch,
        digest: Vec<u8>,
    ) -> Result<Self, PlexiError> {
        if !SIGNATURE_VERSIONS.contains(ciphersuite) {
            return Err(PlexiError::BadParameter("version".to_string()));
        }
        Ok(Self {
            ciphersuite: *ciphersuite,
            namespace,
            timestamp,
            epoch: *epoch,
            digest,
        })
    }

    pub fn ciphersuite(&self) -> &Ciphersuite {
        &self.ciphersuite
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

    #[cfg(feature = "bincode")]
    fn to_vec_bincode(&self) -> Result<Vec<u8>, PlexiError> {
        bincode::encode_to_vec(self, bincode::config::legacy())
            .map_err(|_e| PlexiError::Serialization)
    }

    fn to_vec_proto(&self) -> Result<Vec<u8>, PlexiError> {
        let message = proto::types::SignatureMessage {
            ciphersuite: (*self.ciphersuite()).into(),
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
        match self.ciphersuite {
            Ciphersuite::ProtobufEd25519 => self.to_vec_proto(),
            #[cfg(feature = "bincode")]
            Ciphersuite::BincodeEd25519 => self.to_vec_bincode(),
            _ => Err(PlexiError::Serialization),
        }
    }
}

impl From<SignatureResponse> for SignatureMessage {
    fn from(val: SignatureResponse) -> Self {
        Self {
            ciphersuite: val.ciphersuite,
            namespace: val.namespace,
            timestamp: val.timestamp,
            epoch: val.epoch,
            digest: val.digest,
        }
    }
}

impl From<&SignatureResponse> for SignatureMessage {
    fn from(val: &SignatureResponse) -> Self {
        Self {
            ciphersuite: val.ciphersuite,
            namespace: val.namespace.clone(),
            timestamp: val.timestamp,
            epoch: val.epoch,
            digest: val.digest.clone(),
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

#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct SignatureResponse {
    version: Ciphersuite,
    ciphersuite: Ciphersuite,
    namespace: String,
    timestamp: u64,
    epoch: Epoch,
    digest: Vec<u8>,
    signature: Vec<u8>,
    key_id: Option<u8>,
    serialized_message: Option<Vec<u8>>,
}

impl fmt::Debug for SignatureResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignatureResponse")
            .field("version", &self.version)
            .field("ciphersuite", &self.ciphersuite)
            .field("namespace", &self.namespace)
            .field("timestamp", &self.timestamp)
            .field("epoch", &self.epoch)
            .field("digest", &hex::encode(&self.digest))
            .field("signature", &hex::encode(&self.signature))
            .field("key_id", &self.key_id)
            .field("serialized_message", &self.serialized_message)
            .finish()
    }
}

impl SignatureResponse {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        version: &Ciphersuite,
        ciphersuite: &Ciphersuite,
        namespace: String,
        timestamp: u64,
        epoch: &Epoch,
        digest: Vec<u8>,
        signature: Vec<u8>,
        key_id: Option<u8>,
        serialized_message: Option<Vec<u8>>,
    ) -> Self {
        Self {
            version: *version,
            ciphersuite: *ciphersuite,
            namespace,
            timestamp,
            epoch: *epoch,
            digest,
            signature,
            key_id,
            serialized_message,
        }
    }

    pub fn version(&self) -> &Ciphersuite {
        &self.version
    }
    pub fn ciphersuite(&self) -> &Ciphersuite {
        &self.ciphersuite
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

    pub fn serialized_message(&self) -> Option<Vec<u8>> {
        self.serialized_message.clone()
    }

    pub fn verify(&self, verifying_key: &[u8]) -> anyhow::Result<()> {
        // at the time of writing, all versions use ed25519 keys. This simplifies parsing of the verifying key.
        match self.version {
            Ciphersuite::BincodeEd25519 => {
                if !cfg!(feature = "bincode") {
                    return Err(anyhow!("Verification is not supported for bincode."));
                }
            }
            Ciphersuite::ProtobufEd25519 => (),
            Ciphersuite::Unknown(_) => {
                return Err(anyhow!(
                    "Verification is not supported for the given version."
                ))
            }
        }
        let message: SignatureMessage = self.into();
        let message = message.to_vec()?;

        let verifying_key = verifying_key.try_into().map_err(|_| {
            anyhow!(
                "verifying_key should have length {length}",
                length = ed25519_dalek::PUBLIC_KEY_LENGTH
            )
        })?;
        let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(&verifying_key) else {
            return Err(anyhow!("Cannot parse the provided verifying_key."));
        };

        let Ok(signature) = ed25519_dalek::Signature::from_slice(&self.signature()) else {
            return Err(anyhow!("Cannot construct an Ed25519 signature."));
        };

        verifying_key
            .verify_strict(&message, &signature)
            .map_err(Into::into)
    }
}

// A report request is a signature reponse, except the signature does not come from the auditor (thought to be offline) but from the log provider
pub type Report = SignatureResponse;

impl From<Report> for HashMap<String, String> {
    fn from(val: Report) -> Self {
        let mut map = HashMap::new();
        let version: u32 = (*val.version()).into();
        let ciphersuite: u32 = (*val.ciphersuite()).into();

        map.insert("version".to_string(), version.to_string());
        map.insert("ciphersuite".to_string(), ciphersuite.to_string());
        map.insert("namespace".to_string(), val.namespace().to_string());
        map.insert("timestamp".to_string(), val.timestamp.to_string());
        map.insert("epoch".to_string(), val.epoch.to_string());
        map.insert("digest".to_string(), hex::encode(val.digest));
        map.insert("signature".to_string(), hex::encode(val.signature));
        if let Some(key_id) = val.key_id {
            map.insert("key_id".to_string(), key_id.to_string());
        }
        if let Some(serialized_message) = val.serialized_message {
            map.insert(
                "serialized_message".to_string(),
                hex::encode(serialized_message),
            );
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
            ciphersuite: value
                .get("ciphersuite")
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
            serialized_message: value
                .get("serialized_message")
                .map(hex::decode)
                .transpose()
                .map_err(|_| PlexiError::BadParameter("serialized_message".to_string()))?,
        })
    }
}

#[derive(Deserialize, Serialize)]
struct TempSignatureResponse {
    version: Option<Ciphersuite>,
    ciphersuite: Option<Ciphersuite>,
    namespace: String,
    timestamp: u64,
    epoch: Epoch,
    #[serde(with = "hex::serde")]
    digest: Vec<u8>,
    #[serde(with = "hex::serde")]
    signature: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_id: Option<u8>,
    serialized_message: Option<String>,
}

impl Serialize for SignatureResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let sm = self.serialized_message.as_ref().map(hex::encode);
        let tsp = TempSignatureResponse {
            ciphersuite: Some(self.ciphersuite),
            version: Some(self.ciphersuite),
            namespace: self.namespace.clone(),
            timestamp: self.timestamp,
            epoch: self.epoch,
            digest: self.digest.clone(),
            signature: self.signature.clone(),
            key_id: self.key_id,
            serialized_message: sm,
        };
        tsp.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SignatureResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_signature_response(deserializer)
    }
}

// Mirror ciphersuite to version and vice versa while customer transitions to ciphersuite
fn deserialize_signature_response<'de, D>(deserializer: D) -> Result<SignatureResponse, D::Error>
where
    D: Deserializer<'de>,
{
    let temp = TempSignatureResponse::deserialize(deserializer)?;
    let suite_value = match (temp.version, temp.ciphersuite) {
        (Some(v), _) => v,
        (_, Some(c)) => c,
        _ => {
            return Err(de::Error::missing_field(
                "Either version or ciphersuite must be provided",
            ))
        }
    };
    let sm = temp
        .serialized_message
        .map(hex::decode)
        .transpose()
        .map_err(|_| de::Error::custom("serialized_message should be hex encoded"))?;
    Ok(SignatureResponse {
        version: suite_value,
        ciphersuite: suite_value,
        namespace: temp.namespace,
        timestamp: temp.timestamp,
        epoch: temp.epoch,
        digest: temp.digest,
        signature: temp.signature,
        key_id: temp.key_id,
        serialized_message: sm,
    })
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
            ciphersuite: Ciphersuite,
        }

        let test_vectors: Vec<TestVector> = serde_json::from_str(TEST_VECTORS).unwrap();
        for tv in test_vectors {
            let mut signing_key = ed25519_dalek::SigningKey::from_bytes(&tv.signing_key);
            let verifying_key = signing_key.verifying_key();
            assert_eq!(verifying_key.to_bytes(), tv.verifying_key);

            let key_id = ed25519_public_key_to_key_id(&verifying_key.to_bytes());
            assert_eq!(key_id, tv.key_id);

            let message = SignatureMessage::new(
                &tv.ciphersuite,
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

    #[test]
    fn test_signature_response_serialization() {
        let test_response = SignatureResponse {
            version: Ciphersuite::ProtobufEd25519,
            ciphersuite: Ciphersuite::ProtobufEd25519,
            namespace: "n".to_string(),
            timestamp: 2,
            epoch: Epoch(3),
            digest: vec![4],
            signature: vec![5],
            key_id: Some(6),
            serialized_message: Some(vec![7]),
        };
        let test_json = r#"{"version":1,"ciphersuite":1,"namespace":"n","timestamp":2,"epoch":3,"digest":"04","signature":"05","key_id":6,"serialized_message":"07"}"#;
        let serialized = serde_json::to_string(&test_response).unwrap();
        assert_eq!(serialized, test_json.to_string());
        let deserialized: Result<SignatureResponse, _> = serde_json::from_str(test_json);
        assert!(deserialized.is_ok());
        assert_eq!(deserialized.unwrap(), test_response);
    }
}
