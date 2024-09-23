use core::fmt;

use serde::{Deserialize, Serialize};
#[cfg(feature = "openapi")]
use utoipa::ToSchema;

use crate::{Epoch, PlexiError, SignatureVersion};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct Namespaces {
    namespaces: Vec<NamespaceInfo>,
}

impl Namespaces {
    pub fn new() -> Self {
        Self { namespaces: vec![] }
    }

    pub fn push(&mut self, namespace: NamespaceInfo) {
        self.namespaces.push(namespace);
    }

    pub fn iter(&self) -> impl Iterator<Item = &NamespaceInfo> {
        self.namespaces.iter()
    }
}

impl Default for Namespaces {
    fn default() -> Self {
        Self::new()
    }
}

impl IntoIterator for Namespaces {
    type Item = NamespaceInfo;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.namespaces.into_iter()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct Namespace {
    name: String,
    log_directory: Option<String>,
    root: Option<String>,
    signature_version: SignatureVersion,
}

impl Namespace {
    pub fn new(
        name: String,
        log_directory: Option<String>,
        root: Option<String>,
        signature_version: SignatureVersion,
    ) -> Self {
        Self {
            name,
            log_directory,
            root,
            signature_version,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn log_directory(&self) -> Option<&str> {
        self.log_directory.as_deref()
    }

    pub fn root(&self) -> Option<&str> {
        self.root.as_deref()
    }

    pub fn signature_version(&self) -> &SignatureVersion {
        &self.signature_version
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct NamespaceInfo {
    name: String,
    log_directory: Option<String>,
    root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_verified_epoch: Option<Epoch>,
    status: NamespaceStatus,
    reports_uri: String,
    audits_uri: String,
    signature_version: SignatureVersion,
}

impl NamespaceInfo {
    pub fn new(namespace: &Namespace, status: NamespaceStatus) -> Self {
        Self {
            name: namespace.name().to_string(),
            log_directory: namespace.log_directory().map(str::to_string),
            root: namespace.root().map(str::to_string),
            last_verified_epoch: None,
            status: status.clone(),
            reports_uri: format!("/namespaces/{}/reports", namespace.name()),
            audits_uri: format!("/namespaces/{}/audits", namespace.name()),
            signature_version: *namespace.signature_version(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn log_directory(&self) -> Option<&str> {
        self.log_directory.as_deref()
    }

    pub fn root(&self) -> Option<&str> {
        self.root.as_deref()
    }

    pub fn set_root(&mut self, root: &str) {
        self.root = Some(root.to_string());
    }

    pub fn status(&self) -> NamespaceStatus {
        self.status.clone()
    }

    pub fn set_status(&mut self, status: NamespaceStatus) {
        self.status = status;
    }

    pub fn reports_uri(&self) -> &str {
        &self.reports_uri
    }

    pub fn audits_uri(&self) -> &str {
        &self.audits_uri
    }

    pub fn signature_version(&self) -> SignatureVersion {
        self.signature_version
    }

    pub fn to_string(&self) -> Result<String, PlexiError> {
        serde_json::to_string(self).map_err(|_| PlexiError::Serialization)
    }

    pub fn is_first_epoch(&self, message_root: &str) -> Result<bool, PlexiError> {
        let Some(root) = self.root() else {
            return Ok(self.status == NamespaceStatus::Initialization);
        };

        // TODO: check digest as well
        if root == message_root {
            Ok(true)
        } else if self.status != NamespaceStatus::Initialization {
            Ok(false)
        } else {
            Err(PlexiError::InvalidRoot)
        }
    }

    pub fn set_last_verified_epoch(&mut self, last_verified_epoch: Option<Epoch>) {
        self.last_verified_epoch = last_verified_epoch;
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub enum NamespaceStatus {
    Online,
    Initialization,
    Disabled,
}

impl fmt::Display for NamespaceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Disabled => "Disabled",
            Self::Initialization => "Initialization",
            Self::Online => "Online",
        };
        write!(f, "{}", s)
    }
}
