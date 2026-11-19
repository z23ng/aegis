use std::collections::HashMap;

use anyhow::{bail, Context, Result};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, WWW_AUTHENTICATE};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::debug;

const ACCEPT_MANIFEST: &str = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRef {
    pub registry_display: String,
    pub registry_api: String,
    pub repository: String,
    pub reference: String,
    pub normalized: String,
}

impl ImageRef {
    pub fn parse(raw: &str) -> Result<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            bail!("empty image reference");
        }

        // Split @digest if present, otherwise :tag.
        let (name_part, reference) = if let Some((name, digest)) = trimmed.split_once('@') {
            (name, digest.to_string())
        } else {
            // Find last ':' that is after the last '/'.
            let last_slash = trimmed.rfind('/');
            let last_colon = trimmed.rfind(':');
            match (last_slash, last_colon) {
                (Some(s), Some(c)) if c > s => (&trimmed[..c], trimmed[c + 1..].to_string()),
                (None, Some(c)) => (&trimmed[..c], trimmed[c + 1..].to_string()),
                _ => (trimmed, String::from("latest")),
            }
        };

        let (registry_display, repository) = match name_part.split_once('/') {
            Some((first, rest))
                if first.contains('.') || first.contains(':') || first == "localhost" =>
            {
                (first.to_string(), rest.to_string())
            }
            Some(_) => (String::from("docker.io"), name_part.to_string()),
            None => (String::from("docker.io"), format!("library/{name_part}")),
        };

        let registry_api = if registry_display == "docker.io" || registry_display == "index.docker.io"
        {
            String::from("registry-1.docker.io")
        } else {
            registry_display.clone()
        };

        let normalized = if reference.starts_with("sha256:") {
            format!("{registry_display}/{repository}@{reference}")
        } else {
            format!("{registry_display}/{repository}:{reference}")
        };

        Ok(Self {
            registry_display,
            registry_api,
            repository,
            reference,
            normalized,
        })
    }

    pub fn scheme(&self) -> &'static str {
        if self.registry_api.starts_with("localhost")
            || self.registry_api.starts_with("127.0.0.1")
        {
            "http"
        } else {
            "https"
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DescriptorJson {
    #[serde(rename = "mediaType")]
    pub media_type: Option<String>,
    pub digest: String,
    pub size: i64,
    pub platform: Option<PlatformJson>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PlatformJson {
    pub os: String,
    pub architecture: String,
    pub variant: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ManifestListJson {
    pub manifests: Option<Vec<DescriptorJson>>,
    pub config: Option<DescriptorJson>,
    pub layers: Option<Vec<DescriptorJson>>,
}

#[derive(Debug, Clone)]
pub struct OciManifest {
    pub raw_bytes: Vec<u8>,
    pub digest: String,
    pub media_type: String,
    pub config: DescriptorJson,
    pub layers: Vec<DescriptorJson>,
}

pub struct RegistryClient {
    http: reqwest::Client,
    tokens: HashMap<String, String>,
}

impl RegistryClient {
    pub fn new() -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent("sbx-containerd/0.1")
            .build()
            .context("failed to build reqwest HTTP client")?;
        Ok(Self {
            http,
            tokens: HashMap::new(),
        })
    }

    pub async fn fetch_manifest(&mut self, img: &ImageRef) -> Result<OciManifest> {
        let url = format!(
            "{}://{}/v2/{}/manifests/{}",
            img.scheme(),
            img.registry_api,
            img.repository,
            img.reference
        );
        let (bytes, content_type, hdr_digest) = self.get_with_auth(&url, Some(ACCEPT_MANIFEST)).await?;
        let parsed: ManifestListJson = serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse manifest JSON from {url}"))?;

        if let Some(manifests) = parsed.manifests {
            let selected = select_platform_manifest(&manifests)
                .context("no matching linux platform manifest in multi-arch index")?;
            let sub_url = format!(
                "{}://{}/v2/{}/manifests/{}",
                img.scheme(),
                img.registry_api,
                img.repository,
                selected.digest
            );
            let (sub_bytes, sub_ct, sub_hdr_digest) =
                self.get_with_auth(&sub_url, Some(ACCEPT_MANIFEST)).await?;
            let sub_parsed: ManifestListJson = serde_json::from_slice(&sub_bytes)
                .with_context(|| format!("failed to parse platform manifest {}", selected.digest))?;
            let config = sub_parsed
                .config
                .context("platform manifest missing config descriptor")?;
            let layers = sub_parsed
                .layers
                .context("platform manifest missing layers list")?;
            let digest = sub_hdr_digest.unwrap_or_else(|| sha256_digest(&sub_bytes));
            return Ok(OciManifest {
                raw_bytes: sub_bytes,
                digest,
                media_type: sub_ct
                    .or(selected.media_type.clone())
                    .unwrap_or_else(|| String::from("application/vnd.oci.image.manifest.v1+json")),
                config,
                layers,
            });
        }

        let config = parsed
            .config
            .context("manifest missing config descriptor")?;
        let layers = parsed.layers.context("manifest missing layers list")?;
        let digest = hdr_digest.unwrap_or_else(|| sha256_digest(&bytes));
        Ok(OciManifest {
            raw_bytes: bytes,
            digest,
            media_type: content_type
                .unwrap_or_else(|| String::from("application/vnd.oci.image.manifest.v1+json")),
            config,
            layers,
        })
    }

    pub async fn download_blob(&mut self, img: &ImageRef, digest: &str) -> Result<Vec<u8>> {
        let url = format!(
            "{}://{}/v2/{}/blobs/{}",
            img.scheme(),
            img.registry_api,
            img.repository,
            digest
        );
        let (bytes, _, _) = self.get_with_auth(&url, None).await?;
        let actual = sha256_digest(&bytes);
        if actual != digest {
            bail!("blob digest mismatch: expected {digest}, got {actual}");
        }
        Ok(bytes)
    }

    async fn get_with_auth(
        &mut self,
        url: &str,
        accept: Option<&str>,
    ) -> Result<(Vec<u8>, Option<String>, Option<String>)> {
        let mut headers = HeaderMap::new();
        if let Some(acc) = accept {
            headers.insert(ACCEPT, HeaderValue::from_str(acc)?);
        }
        let host = reqwest::Url::parse(url)?
            .host_str()
            .unwrap_or_default()
            .to_string();
        if let Some(tok) = self.tokens.get(&host) {
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {tok}"))?,
            );
        }

        let resp = self.http.get(url).headers(headers.clone()).send().await?;
        let resp = if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
            let www_auth = resp
                .headers()
                .get(WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            if let Some(challenge) = www_auth {
                let token = self.fetch_bearer_token(&challenge).await?;
                self.tokens.insert(host.clone(), token.clone());
                let mut retry_headers = HeaderMap::new();
                if let Some(acc) = accept {
                    retry_headers.insert(ACCEPT, HeaderValue::from_str(acc)?);
                }
                retry_headers.insert(
                    AUTHORIZATION,
                    HeaderValue::from_str(&format!("Bearer {token}"))?,
                );
                self.http.get(url).headers(retry_headers).send().await?
            } else {
                resp
            }
        } else {
            resp
        };

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("HTTP {status} fetching {url}: {body}");
        }
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let digest_hdr = resp
            .headers()
            .get("Docker-Content-Digest")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let bytes = resp.bytes().await?.to_vec();
        Ok((bytes, content_type, digest_hdr))
    }

    async fn fetch_bearer_token(&self, challenge: &str) -> Result<String> {
        let params = parse_bearer_challenge(challenge)
            .with_context(|| format!("unsupported WWW-Authenticate challenge: {challenge}"))?;
        let realm = params
            .get("realm")
            .context("WWW-Authenticate missing realm")?;

        let mut token_url = reqwest::Url::parse(realm)?;
        {
            let mut pairs = token_url.query_pairs_mut();
            if let Some(service) = params.get("service") {
                pairs.append_pair("service", service);
            }
            if let Some(scope) = params.get("scope") {
                pairs.append_pair("scope", scope);
            }
        }
        debug!(url = %token_url, "fetching registry bearer token");

        #[derive(Deserialize)]
        struct TokenResponse {
            token: Option<String>,
            access_token: Option<String>,
        }
        let resp: TokenResponse = self
            .http
            .get(token_url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        resp.token
            .or(resp.access_token)
            .context("token endpoint returned neither `token` nor `access_token`")
    }
}

fn parse_bearer_challenge(header: &str) -> Option<HashMap<String, String>> {
    let rest = header
        .trim()
        .strip_prefix("Bearer ")
        .or_else(|| header.trim().strip_prefix("bearer "))?;
    let mut map = HashMap::new();
    for part in rest.split(',') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            let val = v.trim().trim_matches('"').to_string();
            map.insert(k.trim().to_string(), val);
        }
    }
    Some(map)
}

fn target_oci_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

fn select_platform_manifest(manifests: &[DescriptorJson]) -> Option<&DescriptorJson> {
    let want_arch = target_oci_arch();
    manifests
        .iter()
        .find(|m| {
            m.platform.as_ref().is_some_and(|p| {
                p.os == "linux"
                    && p.architecture == want_arch
                    && p.variant.as_deref() != Some("unknown")
            })
        })
        .or_else(|| {
            manifests
                .iter()
                .find(|m| m.platform.as_ref().is_some_and(|p| p.os == "linux"))
        })
}

pub fn sha256_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_image_refs() {
        let r = ImageRef::parse("alpine").unwrap();
        assert_eq!(r.normalized, "docker.io/library/alpine:latest");
        assert_eq!(r.registry_api, "registry-1.docker.io");

        let r = ImageRef::parse("python:3.12-slim").unwrap();
        assert_eq!(r.normalized, "docker.io/library/python:3.12-slim");
        assert_eq!(r.repository, "library/python");
        assert_eq!(r.reference, "3.12-slim");

        let r = ImageRef::parse("ghcr.io/foo/bar:v2").unwrap();
        assert_eq!(r.normalized, "ghcr.io/foo/bar:v2");
        assert_eq!(r.registry_api, "ghcr.io");
    }
}
