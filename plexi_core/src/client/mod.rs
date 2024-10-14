use core::fmt;
use std::time::Duration;

use crate::auditor::Configuration as AuditorConfiguration;
use crate::namespaces::{NamespaceInfo, Namespaces};
use crate::{Epoch, LastVerifiedEpoch, SignatureResponse};
use akd::local_auditing::AuditBlobName;
use anyhow::{anyhow, Context as _};
use reqwest::{Certificate, Client, Identity, StatusCode, Url};
use serde::de::DeserializeOwned;

#[derive(Clone)]
pub struct PlexiClient {
    base_url: Url,
    client: Client,
}

impl fmt::Debug for PlexiClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "plexi@{}", self.base_url)
    }
}

impl PlexiClient {
    pub fn new(
        base_url: Url,
        mtls: Option<ClientMtls>,
        user_agent: Option<&str>,
    ) -> anyhow::Result<Self> {
        let mut client_builder = Client::builder();

        if let Ok(bundle) = std::env::var("SSL_CERT_FILE") {
            let certs = std::fs::read(&bundle)
                .with_context(|| format!("reading cert bundle at: {bundle}"))?;

            for cert in Certificate::from_pem_bundle(&certs)
                .with_context(|| format!("parsing cert bundle at: {bundle}"))?
            {
                client_builder = client_builder.add_root_certificate(cert);
            }
        }

        if let Ok("1") = std::env::var("SSL_ACCEPT_INVALID_CERTS").as_deref() {
            client_builder = client_builder
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true);
        }

        if let Some(mtls) = mtls {
            client_builder = client_builder.identity(mtls.identity);
        }

        if let Some(user_agent) = user_agent {
            client_builder = client_builder.user_agent(user_agent);
        }

        Ok(Self {
            base_url,
            client: client_builder
                .connect_timeout(Duration::from_secs(30))
                .timeout(Duration::from_secs(60))
                .build()
                .context("building plexi api client")?,
        })
    }

    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    pub fn client(&self) -> &Client {
        &self.client
    }

    async fn fetch_json<T>(&self, url: &Url) -> anyhow::Result<Option<T>>
    where
        T: DeserializeOwned,
    {
        let response = self.client.get(url.clone()).send().await?;

        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        Ok(Some(
            response
                .error_for_status()
                .with_context(|| format!("fetching {url}"))?
                .json()
                .await
                .context(format!("converting {url} into json"))?,
        ))
    }

    pub async fn auditor_config(&self) -> anyhow::Result<AuditorConfiguration> {
        let url = self.base_url.join("/info")?;

        match self.fetch_json(&url).await? {
            Some(config) => Ok(config),
            None => Err(anyhow!("auditor configuration should alwasys be defined")),
        }
    }

    pub async fn namespace(&self, namespace: &str) -> anyhow::Result<Option<NamespaceInfo>> {
        let url = self.base_url.join(&format!("/namespaces/{namespace}"))?;

        self.fetch_json(&url).await
    }

    pub async fn namespaces(&self) -> anyhow::Result<Namespaces> {
        let url = self.base_url.join("/namespaces")?;

        match self.fetch_json(&url).await? {
            Some(namespaces) => Ok(namespaces),
            None => Err(anyhow!("auditor configuration should alwasys be defined")),
        }
    }

    pub async fn signature(
        &self,
        namespace: &str,
        epoch: &Epoch,
    ) -> anyhow::Result<Option<SignatureResponse>> {
        let url = self
            .base_url
            .join(&format!("/namespaces/{namespace}/audits/{epoch}"))?;

        self.fetch_json(&url).await
    }

    pub async fn last_verified_epoch(
        &self,
        namespace: &str,
    ) -> anyhow::Result<Option<LastVerifiedEpoch>> {
        let url = self
            .base_url
            .join(&format!("/namespaces/{namespace}/last-verified-epoch"))?;

        self.fetch_json(&url).await
    }

    pub async fn proof(
        &self,
        blob: &AuditBlobName,
        directory_url: Option<&str>,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        // to be replaced with a default to self.base_url/proofs once available
        let Some(directory_url) = directory_url else {
            return Err(anyhow!(
                "plexi does not provide proof retrieval at this time."
            ));
        };

        let url = Url::parse(directory_url)?;
        let url = url.join(&format!("/{blob}", blob = blob.to_string()))?;

        let response = self.client.get(url.clone()).send().await?;

        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        Ok(Some(
            response
                .error_for_status()
                .with_context(|| format!("fetching {url}"))?
                .bytes()
                .await?
                .to_vec(),
        ))
    }
}

#[derive(Clone)]
pub struct ClientMtls {
    identity: Identity,
}

impl ClientMtls {
    pub fn new(cert: &[u8], key: &[u8]) -> anyhow::Result<Self> {
        let identity =
            Identity::from_pkcs8_pem(cert, key).context("creating identity from pkcs8 pem")?;

        Ok(ClientMtls { identity })
    }
}
