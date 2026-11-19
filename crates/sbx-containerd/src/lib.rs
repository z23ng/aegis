pub mod bootstrap;
pub mod registry;
pub mod unpack;

use std::collections::HashMap;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use chrono::Utc;
use containerd_client::services::v1::{
    snapshots::{
        snapshots_client::SnapshotsClient, CommitSnapshotRequest, PrepareSnapshotRequest,
        RemoveSnapshotRequest, StatSnapshotRequest,
    },
    content_client::ContentClient,
    images_client::ImagesClient,
    leases_client::LeasesClient,
    namespaces_client::NamespacesClient,
    CreateImageRequest, CreateNamespaceRequest, DeleteRequest as DeleteLeaseRequest,
    GetImageRequest, GetNamespaceRequest, Image as CtdImage, InfoRequest as ContentInfoRequest,
    ListImagesRequest, ListRequest as ListLeasesRequest, Namespace, UpdateImageRequest,
    WriteAction, WriteContentRequest, CreateRequest as CreateLeaseRequest,
};
use containerd_client::types::Descriptor as CtdDescriptor;
use containerd_client::Client;
use sbx_proto::{DiffKind, FsDiffEntry, SandboxId, SnapshotMeta};
use serde::{Deserialize, Serialize};
use tokio_stream::iter as stream_iter;
use tonic::{Code, Request, Status};
use tracing::{debug, info, warn};

use crate::bootstrap::{ensure_local_containerd_running, resolve_socket_path};
use crate::registry::{ImageRef, RegistryClient};
use crate::unpack::{compute_chain_id, compute_layer_diff_id, unpack_layer_tar};

pub const DEFAULT_NAMESPACE: &str = "sbx";
pub const DEFAULT_SNAPSHOTTER: &str = "overlayfs";

const LABEL_CHAIN_ID: &str = "sbx.io/chain-id";
const LABEL_SANDBOX_ID: &str = "sbx.io/sandbox-id";
const LABEL_EXPIRE_UNIX: &str = "sbx.io/expire-unix";
const LABEL_GC_EXPIRE: &str = "containerd.io/gc.expire";
const LABEL_GC_SNAPSHOT_REF: &str = "containerd.io/gc.ref.snapshot.overlayfs";

/// Mount instruction returned by containerd snapshotter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountSpec {
    pub r#type: String,
    pub source: String,
    pub target: String,
    pub options: Vec<String>,
}

/// Result of pulling and unpacking an OCI image into containerd.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PulledImage {
    pub reference: String,
    pub digest: String,
    pub chain_id: String,
    pub cached: bool,
}

/// Prepared active OverlayFS rootfs + lease for a sandbox instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedRootfs {
    pub sandbox_id: String,
    pub image: PulledImage,
    pub snapshot_key: String,
    pub lease_id: String,
    pub mounts: Vec<MountSpec>,
}

/// Summary of an image stored in containerd.
#[derive(Debug, Clone)]
pub struct ImageSummary {
    pub name: String,
    pub digest: String,
    pub chain_id: Option<String>,
}

/// High-level client wrapping `containerd` gRPC services (`Images`, `Content`, `Snapshots`, `Leases`).
pub struct ContainerdClientAdapter {
    client: Client,
    socket_path: PathBuf,
    namespace: String,
    snapshotter: String,
}

impl Clone for ContainerdClientAdapter {
    fn clone(&self) -> Self {
        Self {
            client: Client::from(self.client.channel()),
            socket_path: self.socket_path.clone(),
            namespace: self.namespace.clone(),
            snapshotter: self.snapshotter.clone(),
        }
    }
}

impl ContainerdClientAdapter {
    /// Connect to `containerd` (auto-bootstrapping a local rootless daemon if needed) and ensure namespace exists.
    pub async fn connect(explicit_socket: Option<&Path>) -> Result<Self> {
        let socket_path = resolve_socket_path(explicit_socket);
        ensure_local_containerd_running(&socket_path).await?;
        let client = Client::from_path(&socket_path)
            .await
            .with_context(|| format!("failed to connect to containerd at {}", socket_path.display()))?;

        let adapter = Self {
            client,
            socket_path,
            namespace: String::from(DEFAULT_NAMESPACE),
            snapshotter: String::from(DEFAULT_SNAPSHOTTER),
        };
        adapter.ensure_namespace().await?;
        Ok(adapter)
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn snapshotter(&self) -> &str {
        &self.snapshotter
    }

    pub async fn server_version(&self) -> Result<(String, String)> {
        let resp = self
            .client
            .version()
            .version(Request::new(()))
            .await?
            .into_inner();
        Ok((resp.version, resp.revision))
    }

    fn req<T>(&self, inner: T, lease: Option<&str>) -> Result<Request<T>> {
        let mut r = Request::new(inner);
        let md = r.metadata_mut();
        md.insert(
            "containerd-namespace",
            self.namespace
                .parse()
                .context("invalid containerd-namespace header")?,
        );
        if let Some(l) = lease {
            md.insert(
                "containerd-lease",
                l.parse().context("invalid containerd-lease header")?,
            );
        }
        Ok(r)
    }

    pub async fn ensure_namespace(&self) -> Result<()> {
        let mut ns_client: NamespacesClient<_> = self.client.namespaces();
        match ns_client
            .get(Request::new(GetNamespaceRequest {
                name: self.namespace.clone(),
            }))
            .await
        {
            Ok(_) => Ok(()),
            Err(status) if status.code() == Code::NotFound => {
                match ns_client
                    .create(Request::new(CreateNamespaceRequest {
                        namespace: Some(Namespace {
                            name: self.namespace.clone(),
                            labels: HashMap::new(),
                        }),
                    }))
                    .await
                {
                    Ok(_) => Ok(()),
                    Err(e) if e.code() == Code::AlreadyExists => Ok(()),
                    Err(e) => Err(e.into()),
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Create a GC-protected containerd Lease tied to `sandbox_id` and `ttl`.
    pub async fn create_lease(&self, sandbox_id: &str, ttl: Duration) -> Result<String> {
        let lease_id = format!("sbx-lease-{sandbox_id}");
        let chrono_ttl =
            chrono::Duration::from_std(ttl).unwrap_or_else(|_| chrono::Duration::hours(1));
        let expire_at = Utc::now() + chrono_ttl;
        let expire_unix = expire_at.timestamp();

        let mut labels = HashMap::new();
        labels.insert(String::from(LABEL_GC_EXPIRE), expire_at.to_rfc3339());
        labels.insert(String::from(LABEL_SANDBOX_ID), sandbox_id.to_string());
        labels.insert(String::from(LABEL_EXPIRE_UNIX), expire_unix.to_string());

        let mut leases: LeasesClient<_> = self.client.leases();
        let req = self.req(
            CreateLeaseRequest {
                id: lease_id.clone(),
                labels,
            },
            None,
        )?;
        match leases.create(req).await {
            Ok(_) => Ok(lease_id),
            Err(status) if status.code() == Code::AlreadyExists => {
                self.delete_lease(&lease_id).await?;
                let mut labels = HashMap::new();
                labels.insert(String::from(LABEL_GC_EXPIRE), expire_at.to_rfc3339());
                labels.insert(String::from(LABEL_SANDBOX_ID), sandbox_id.to_string());
                labels.insert(String::from(LABEL_EXPIRE_UNIX), expire_unix.to_string());
                let retry = self.req(
                    CreateLeaseRequest {
                        id: lease_id.clone(),
                        labels,
                    },
                    None,
                )?;
                leases.create(retry).await?;
                Ok(lease_id)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Delete a containerd Lease (ignoring NotFound).
    pub async fn delete_lease(&self, lease_id: &str) -> Result<()> {
        let mut leases: LeasesClient<_> = self.client.leases();
        let req = self.req(
            DeleteLeaseRequest {
                id: lease_id.to_string(),
                sync: false,
            },
            None,
        )?;
        match leases.delete(req).await {
            Ok(_) => Ok(()),
            Err(s) if s.code() == Code::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Clean up any expired `sbx-lease-*` entries and their active snapshots.
    pub async fn reap_expired_leases(&self) -> Result<usize> {
        let mut leases: LeasesClient<_> = self.client.leases();
        let resp = leases
            .list(self.req(ListLeasesRequest { filters: Vec::new() }, None)?)
            .await?
            .into_inner();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let mut reaped = 0;
        for lease in resp.leases {
            let expired = lease
                .labels
                .get(LABEL_EXPIRE_UNIX)
                .and_then(|v| v.parse::<i64>().ok())
                .is_some_and(|exp| exp < now);
            if expired {
                if let Some(sbx_id) = lease.labels.get(LABEL_SANDBOX_ID) {
                    let _ = self.remove_snapshot(&format!("sbx-active-{sbx_id}")).await;
                }
                let _ = self.delete_lease(&lease.id).await;
                reaped += 1;
            }
        }
        Ok(reaped)
    }

    /// List all images registered in the `sbx` containerd namespace.
    pub async fn list_images(&self) -> Result<Vec<ImageSummary>> {
        let mut images: ImagesClient<_> = self.client.images();
        let resp = images
            .list(self.req(ListImagesRequest { filters: Vec::new() }, None)?)
            .await?
            .into_inner();
        Ok(resp
            .images
            .into_iter()
            .map(|img| ImageSummary {
                name: img.name,
                digest: img.target.map(|t| t.digest).unwrap_or_default(),
                chain_id: img.labels.get(LABEL_CHAIN_ID).cloned(),
            })
            .collect())
    }

    /// Pull an OCI image (or return immediately from local containerd cache if already unpacked).
    pub async fn pull_image(&self, raw_ref: &str) -> Result<PulledImage> {
        let img_ref = ImageRef::parse(raw_ref)?;

        // Fast path: image metadata + committed snapshot already present in containerd.
        if let Some(cached) = self.try_cached_image(&img_ref.normalized).await? {
            debug!(image = %img_ref.normalized, chain_id = %cached.chain_id, "image cache hit");
            return Ok(cached);
        }

        info!(image = %img_ref.normalized, "pulling OCI image from registry");
        let pull_lease_id = format!(
            "sbx-pull-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let pull_lease = self
            .create_lease(&pull_lease_id, Duration::from_secs(600))
            .await?;

        let res = self.pull_image_with_lease(&img_ref, &pull_lease).await;
        let _ = self.delete_lease(&pull_lease).await;
        res
    }

    async fn pull_image_with_lease(
        &self,
        img_ref: &ImageRef,
        pull_lease: &str,
    ) -> Result<PulledImage> {
        let mut registry = RegistryClient::new()?;
        let manifest = registry.fetch_manifest(img_ref).await?;

        let mut manifest_labels = HashMap::new();
        manifest_labels.insert(
            String::from("containerd.io/gc.ref.content.0"),
            manifest.config.digest.clone(),
        );
        for (idx, layer) in manifest.layers.iter().enumerate() {
            manifest_labels.insert(
                format!("containerd.io/gc.ref.content.{}", idx + 1),
                layer.digest.clone(),
            );
        }

        // Write manifest and config into containerd Content Store under the pull lease.
        self.write_content_if_missing(
            &manifest.digest,
            &manifest.raw_bytes,
            Some(pull_lease),
            manifest_labels,
        )
        .await?;
        let config_bytes = registry
            .download_blob(img_ref, &manifest.config.digest)
            .await?;
        self.write_content_if_missing(
            &manifest.config.digest,
            &config_bytes,
            Some(pull_lease),
            HashMap::new(),
        )
        .await?;

        let mut parent_chain_id: Option<String> = None;
        let mut lower_dirs: Vec<PathBuf> = Vec::new();

        for (idx, layer) in manifest.layers.iter().enumerate() {
            debug!(
                layer = idx,
                digest = %layer.digest,
                size = layer.size,
                "fetching and unpacking OCI layer"
            );
            let compressed = registry.download_blob(img_ref, &layer.digest).await?;
            self.write_content_if_missing(
                &layer.digest,
                &compressed,
                Some(pull_lease),
                HashMap::new(),
            )
            .await?;

            let diff_id = compute_layer_diff_id(&compressed, layer.media_type.as_deref())?;
            let chain_id = compute_chain_id(parent_chain_id.as_deref(), &diff_id);

            if !self.snapshot_exists(&chain_id).await? {
                let extract_key = format!(
                    "sbx-extract-{}-{}",
                    idx,
                    chain_id.trim_start_matches("sha256:")
                );
                let _ = self.remove_snapshot(&extract_key).await;

                let mut snaps: SnapshotsClient<_> = self.client.snapshots();
                let prep_resp = snaps
                    .prepare(self.req(
                        PrepareSnapshotRequest {
                            snapshotter: self.snapshotter.clone(),
                            key: extract_key.clone(),
                            parent: parent_chain_id.clone().unwrap_or_default(),
                            labels: HashMap::new(),
                        },
                        Some(pull_lease),
                    )?)
                    .await?
                    .into_inner();

                let target_dir = extract_upper_dir(&prep_resp.mounts)
                    .context("containerd prepare did not return a writable target directory")?;

                let lower_snapshot = lower_dirs.clone();
                let layer_mt = layer.media_type.clone();
                let unpacked_diff_id = tokio::task::spawn_blocking(move || {
                    unpack_layer_tar(
                        &compressed,
                        layer_mt.as_deref(),
                        &target_dir,
                        &lower_snapshot,
                    )
                })
                .await??;

                if unpacked_diff_id != diff_id {
                    warn!(
                        expected = %diff_id,
                        actual = %unpacked_diff_id,
                        "layer diff_id mismatch during unpack"
                    );
                }

                match snaps
                    .commit(self.req(
                        CommitSnapshotRequest {
                            snapshotter: self.snapshotter.clone(),
                            name: chain_id.clone(),
                            key: extract_key.clone(),
                            labels: HashMap::new(),
                        },
                        Some(pull_lease),
                    )?)
                    .await
                {
                    Ok(_) => {}
                    Err(s) if s.code() == Code::AlreadyExists => {
                        let _ = self.remove_snapshot(&extract_key).await;
                    }
                    Err(e) => {
                        let _ = self.remove_snapshot(&extract_key).await;
                        return Err(e.into());
                    }
                }
            }

            // Track committed snapshot fs path for potential whiteout resolution in subsequent layers.
            if let Some(dir) = self.snapshot_fs_dir(&chain_id, Some(pull_lease)).await? {
                lower_dirs.insert(0, dir);
            }
            parent_chain_id = Some(chain_id);
        }

        let final_chain_id = parent_chain_id.context("image manifest contained zero layers")?;

        // Record image metadata in containerd Images service with GC refs to content + snapshot chain.
        let mut labels = HashMap::new();
        labels.insert(String::from(LABEL_CHAIN_ID), final_chain_id.clone());
        labels.insert(String::from(LABEL_GC_SNAPSHOT_REF), final_chain_id.clone());
        labels.insert(
            String::from("containerd.io/gc.ref.content.0"),
            manifest.digest.clone(),
        );

        let ctd_img = CtdImage {
            name: img_ref.normalized.clone(),
            labels,
            target: Some(CtdDescriptor {
                media_type: manifest.media_type,
                digest: manifest.digest.clone(),
                size: manifest.raw_bytes.len() as i64,
                annotations: HashMap::new(),
            }),
            created_at: None,
            updated_at: None,
        };

        let mut images: ImagesClient<_> = self.client.images();
        match images
            .create(self.req(
                CreateImageRequest {
                    image: Some(ctd_img.clone()),
                    source_date_epoch: None,
                },
                None,
            )?)
            .await
        {
            Ok(_) => {}
            Err(s) if s.code() == Code::AlreadyExists => {
                images
                    .update(self.req(
                        UpdateImageRequest {
                            image: Some(ctd_img),
                            update_mask: None,
                            source_date_epoch: None,
                        },
                        None,
                    )?)
                    .await?;
            }
            Err(e) => return Err(e.into()),
        }

        Ok(PulledImage {
            reference: img_ref.normalized.clone(),
            digest: manifest.digest,
            chain_id: final_chain_id,
            cached: false,
        })
    }

    /// Prepare a writable OverlayFS snapshot and GC Lease for `sandbox_id`.
    pub async fn prepare_rootfs(
        &self,
        sandbox_id: &str,
        image_ref: &str,
        ttl: Duration,
    ) -> Result<PreparedRootfs> {
        let image = self.pull_image(image_ref).await?;
        let lease_id = self.create_lease(sandbox_id, ttl).await?;
        let snapshot_key = format!("sbx-active-{sandbox_id}");

        let mut snaps: SnapshotsClient<_> = self.client.snapshots();
        let prep_req = PrepareSnapshotRequest {
            snapshotter: self.snapshotter.clone(),
            key: snapshot_key.clone(),
            parent: image.chain_id.clone(),
            labels: HashMap::from([(String::from(LABEL_SANDBOX_ID), sandbox_id.to_string())]),
        };

        let resp = match snaps.prepare(self.req(prep_req, Some(&lease_id))?).await {
            Ok(r) => r.into_inner(),
            Err(s) if s.code() == Code::AlreadyExists => {
                self.remove_snapshot(&snapshot_key).await?;
                let retry = PrepareSnapshotRequest {
                    snapshotter: self.snapshotter.clone(),
                    key: snapshot_key.clone(),
                    parent: image.chain_id.clone(),
                    labels: HashMap::from([(
                        String::from(LABEL_SANDBOX_ID),
                        sandbox_id.to_string(),
                    )]),
                };
                snaps
                    .prepare(self.req(retry, Some(&lease_id))?)
                    .await?
                    .into_inner()
            }
            Err(e) => return Err(e.into()),
        };

        let mounts = resp
            .mounts
            .into_iter()
            .map(|m| MountSpec {
                r#type: m.r#type,
                source: m.source,
                target: m.target,
                options: m.options,
            })
            .collect();

        Ok(PreparedRootfs {
            sandbox_id: sandbox_id.to_string(),
            image,
            snapshot_key,
            lease_id,
            mounts,
        })
    }

    /// Clean up active snapshot and GC lease for `sandbox_id` (idempotent).
    pub async fn cleanup_sandbox_storage(&self, sandbox_id: &str) -> Result<()> {
        let snapshot_key = format!("sbx-active-{sandbox_id}");
        let lease_id = format!("sbx-lease-{sandbox_id}");
        self.remove_snapshot(&snapshot_key).await?;
        self.delete_lease(&lease_id).await?;
        Ok(())
    }

    /// Compute filesystem changes (`Added`, `Modified`, `Deleted`) in a sandbox's OverlayFS upperdir.
    pub fn diff_sandbox_rootfs(&self, mounts: &[MountSpec]) -> Result<Vec<FsDiffEntry>> {
        let (Some(upper), lowers) = extract_overlay_dirs(mounts) else {
            return Ok(Vec::new());
        };
        if !upper.is_dir() {
            return Ok(Vec::new());
        }
        compute_dir_diff(&upper, &lowers)
    }

    /// Commit the current active sandbox `upperdir` into an immutable step-level `containerd` snapshot
    /// (`snap-{sandbox_id}-{seq}`) without interrupting the running sandbox.
    pub async fn create_step_snapshot(
        &self,
        sandbox_id: &str,
        parent_chain_id: &str,
        active_mounts: &[MountSpec],
        label: Option<&str>,
        ttl: Duration,
    ) -> Result<SnapshotMeta> {
        static SNAP_SEQ: AtomicU64 = AtomicU64::new(1);
        let seq = SNAP_SEQ.fetch_add(1, Ordering::Relaxed);
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let snapshot_id = format!("snap-{sandbox_id}-{now_unix}-{seq}");
        let prep_key = format!("sbx-commit-tmp-{snapshot_id}");
        let _ = self.remove_snapshot(&prep_key).await;

        let lease_id = self.create_lease(&snapshot_id, ttl).await?;
        let mut snaps: SnapshotsClient<_> = self.client.snapshots();
        let prep_resp = snaps
            .prepare(self.req(
                PrepareSnapshotRequest {
                    snapshotter: self.snapshotter.clone(),
                    key: prep_key.clone(),
                    parent: parent_chain_id.to_string(),
                    labels: HashMap::from([
                        (String::from(LABEL_SANDBOX_ID), sandbox_id.to_string()),
                        (String::from("sbx.io/snapshot-id"), snapshot_id.clone()),
                    ]),
                },
                Some(&lease_id),
            )?)
            .await?
            .into_inner();

        let target_dir = extract_upper_dir(&prep_resp.mounts)
            .context("containerd prepare did not return a writable target directory")?;

        if let (Some(src_upper), _) = extract_overlay_dirs(active_mounts) {
            if src_upper.is_dir() {
                tokio::task::spawn_blocking(move || copy_overlay_upper(&src_upper, &target_dir))
                    .await??;
            }
        }

        let mut commit_labels = HashMap::from([
            (String::from(LABEL_SANDBOX_ID), sandbox_id.to_string()),
            (String::from("sbx.io/snapshot-id"), snapshot_id.clone()),
        ]);
        if let Some(lbl) = label {
            commit_labels.insert(String::from("sbx.io/snapshot-label"), lbl.to_string());
        }

        snaps
            .commit(self.req(
                CommitSnapshotRequest {
                    snapshotter: self.snapshotter.clone(),
                    name: snapshot_id.clone(),
                    key: prep_key.clone(),
                    labels: commit_labels,
                },
                Some(&lease_id),
            )?)
            .await?;

        Ok(SnapshotMeta {
            id: snapshot_id,
            sandbox_id: SandboxId::from(sandbox_id),
            parent_id: if parent_chain_id.is_empty() {
                None
            } else {
                Some(parent_chain_id.to_string())
            },
            label: label.map(str::to_string),
            created_at_unix: now_unix,
        })
    }

    /// Discard the active writable layer for `sandbox_id` and mount a clean CoW layer from `snapshot_id`.
    pub async fn rollback_to_snapshot(
        &self,
        sandbox_id: &str,
        snapshot_id: &str,
        ttl: Duration,
    ) -> Result<PreparedRootfs> {
        let snapshot_key = format!("sbx-active-{sandbox_id}");
        self.remove_snapshot(&snapshot_key).await?;
        self.prepare_from_snapshot(sandbox_id, snapshot_id, snapshot_id, ttl)
            .await
    }

    /// Create an independent writable CoW rootfs for `new_sandbox_id` forked from `snapshot_id`.
    pub async fn fork_from_snapshot(
        &self,
        snapshot_id: &str,
        new_sandbox_id: &str,
        ttl: Duration,
    ) -> Result<PreparedRootfs> {
        self.prepare_from_snapshot(new_sandbox_id, snapshot_id, snapshot_id, ttl)
            .await
    }

    /// Prepare a writable OverlayFS snapshot from an existing committed snapshot key (`chain_id` or `snap-*`).
    pub async fn prepare_from_snapshot(
        &self,
        sandbox_id: &str,
        snapshot_id: &str,
        image_ref: &str,
        ttl: Duration,
    ) -> Result<PreparedRootfs> {
        let lease_id = self.create_lease(sandbox_id, ttl).await?;
        let snapshot_key = format!("sbx-active-{sandbox_id}");
        let _ = self.remove_snapshot(&snapshot_key).await;

        let mut snaps: SnapshotsClient<_> = self.client.snapshots();
        let resp = snaps
            .prepare(self.req(
                PrepareSnapshotRequest {
                    snapshotter: self.snapshotter.clone(),
                    key: snapshot_key.clone(),
                    parent: snapshot_id.to_string(),
                    labels: HashMap::from([(String::from(LABEL_SANDBOX_ID), sandbox_id.to_string())]),
                },
                Some(&lease_id),
            )?)
            .await?
            .into_inner();

        let mounts = resp
            .mounts
            .into_iter()
            .map(|m| MountSpec {
                r#type: m.r#type,
                source: m.source,
                target: m.target,
                options: m.options,
            })
            .collect();

        Ok(PreparedRootfs {
            sandbox_id: sandbox_id.to_string(),
            image: PulledImage {
                reference: image_ref.to_string(),
                digest: String::new(),
                chain_id: snapshot_id.to_string(),
                cached: true,
            },
            snapshot_key,
            lease_id,
            mounts,
        })
    }

    /// Remove a committed step snapshot and its lease (idempotent).
    pub async fn remove_step_snapshot(&self, snapshot_id: &str) -> Result<()> {
        self.remove_snapshot(snapshot_id).await?;
        self.delete_lease(&format!("sbx-lease-{snapshot_id}"))
            .await?;
        Ok(())
    }

    async fn try_cached_image(&self, normalized_name: &str) -> Result<Option<PulledImage>> {
        let mut images: ImagesClient<_> = self.client.images();
        let resp = match images
            .get(self.req(
                GetImageRequest {
                    name: normalized_name.to_string(),
                },
                None,
            )?)
            .await
        {
            Ok(r) => r.into_inner(),
            Err(s) if s.code() == Code::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        let Some(img) = resp.image else {
            return Ok(None);
        };
        let Some(chain_id) = img.labels.get(LABEL_CHAIN_ID).cloned() else {
            return Ok(None);
        };
        if !self.snapshot_exists(&chain_id).await? {
            return Ok(None);
        }

        Ok(Some(PulledImage {
            reference: img.name,
            digest: img.target.map(|t| t.digest).unwrap_or_default(),
            chain_id,
            cached: true,
        }))
    }

    async fn snapshot_exists(&self, key: &str) -> Result<bool> {
        let mut snaps: SnapshotsClient<_> = self.client.snapshots();
        match snaps
            .stat(self.req(
                StatSnapshotRequest {
                    snapshotter: self.snapshotter.clone(),
                    key: key.to_string(),
                },
                None,
            )?)
            .await
        {
            Ok(_) => Ok(true),
            Err(s) if s.code() == Code::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    async fn remove_snapshot(&self, key: &str) -> Result<()> {
        let mut snaps: SnapshotsClient<_> = self.client.snapshots();
        match snaps
            .remove(self.req(
                RemoveSnapshotRequest {
                    snapshotter: self.snapshotter.clone(),
                    key: key.to_string(),
                },
                None,
            )?)
            .await
        {
            Ok(_) => Ok(()),
            Err(s) if s.code() == Code::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    async fn snapshot_fs_dir(&self, key: &str, lease: Option<&str>) -> Result<Option<PathBuf>> {
        let view_key = format!("sbx-view-{}", key.trim_start_matches("sha256:"));
        let _ = self.remove_snapshot(&view_key).await;
        let mut snaps: SnapshotsClient<_> = self.client.snapshots();
        let resp = snaps
            .view(self.req(
                containerd_client::services::v1::snapshots::ViewSnapshotRequest {
                    snapshotter: self.snapshotter.clone(),
                    key: view_key.clone(),
                    parent: key.to_string(),
                    labels: HashMap::new(),
                },
                lease,
            )?)
            .await;
        let dir = match resp {
            Ok(r) => {
                let mounts = r.into_inner().mounts;
                mounts.first().and_then(|m| {
                    if m.r#type == "bind" {
                        Some(PathBuf::from(&m.source))
                    } else {
                        m.options
                            .iter()
                            .find_map(|o| o.strip_prefix("lowerdir="))
                            .and_then(|l| l.split(':').next())
                            .map(PathBuf::from)
                    }
                })
            }
            Err(_) => None,
        };
        let _ = self.remove_snapshot(&view_key).await;
        Ok(dir)
    }

    async fn write_content_if_missing(
        &self,
        digest: &str,
        data: &[u8],
        lease: Option<&str>,
        labels: HashMap<String, String>,
    ) -> Result<()> {
        let mut content: ContentClient<_> = self.client.content();
        match content
            .info(self.req(
                ContentInfoRequest {
                    digest: digest.to_string(),
                },
                lease,
            )?)
            .await
        {
            Ok(_) => return Ok(()),
            Err(s) if s.code() == Code::NotFound => {}
            Err(e) => return Err(e.into()),
        }

        const CHUNK_SIZE: usize = 1024 * 1024;
        let total = data.len() as i64;
        let write_ref = format!("sbx-ingest-{digest}");
        let mut requests = Vec::new();

        if data.is_empty() {
            requests.push(WriteContentRequest {
                action: WriteAction::Commit as i32,
                r#ref: write_ref.clone(),
                total: 0,
                expected: digest.to_string(),
                offset: 0,
                data: Vec::new(),
                labels: labels.clone(),
            });
        } else {
            let chunks: Vec<&[u8]> = data.chunks(CHUNK_SIZE).collect();
            let last_idx = chunks.len() - 1;
            let mut offset: i64 = 0;
            for (idx, chunk) in chunks.into_iter().enumerate() {
                let action = if idx == last_idx {
                    WriteAction::Commit as i32
                } else {
                    WriteAction::Write as i32
                };
                requests.push(WriteContentRequest {
                    action,
                    r#ref: if idx == 0 {
                        write_ref.clone()
                    } else {
                        String::new()
                    },
                    total: if idx == 0 || idx == last_idx { total } else { 0 },
                    expected: if idx == 0 || idx == last_idx {
                        digest.to_string()
                    } else {
                        String::new()
                    },
                    offset,
                    data: chunk.to_vec(),
                    labels: if idx == last_idx {
                        labels.clone()
                    } else {
                        HashMap::new()
                    },
                });
                offset += chunk.len() as i64;
            }
        }

        let mut req = self.req(stream_iter(requests), lease)?;
        // Set standard write ref header just in case.
        let _ = &mut req;
        match content.write(req).await {
            Ok(resp) => {
                let mut stream = resp.into_inner();
                while let Some(msg) = stream.message().await? {
                    if msg.action == WriteAction::Commit as i32 {
                        break;
                    }
                }
                Ok(())
            }
            Err(status) if is_already_exists(&status) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

fn is_already_exists(status: &Status) -> bool {
    status.code() == Code::AlreadyExists
        || status.message().contains("already exists")
}

fn extract_upper_dir(mounts: &[containerd_client::types::Mount]) -> Option<PathBuf> {
    for m in mounts {
        if m.r#type == "bind" && !m.source.is_empty() {
            return Some(PathBuf::from(&m.source));
        }
        if m.r#type == "overlay" {
            for opt in &m.options {
                if let Some(upper) = opt.strip_prefix("upperdir=") {
                    return Some(PathBuf::from(upper));
                }
            }
        }
    }
    None
}

/// Extract `(upperdir, lowerdirs)` from `MountSpec` slices.
pub fn extract_overlay_dirs(mounts: &[MountSpec]) -> (Option<PathBuf>, Vec<PathBuf>) {
    let mut upper = None;
    let mut lowers = Vec::new();
    for m in mounts {
        if m.r#type == "bind" && !m.source.is_empty() && upper.is_none() {
            upper = Some(PathBuf::from(&m.source));
        }
        if m.r#type == "overlay" {
            for opt in &m.options {
                if let Some(u) = opt.strip_prefix("upperdir=") {
                    upper = Some(PathBuf::from(u));
                } else if let Some(l) = opt.strip_prefix("lowerdir=") {
                    for part in l.split(':') {
                        if !part.is_empty() {
                            lowers.push(PathBuf::from(part));
                        }
                    }
                }
            }
        }
    }
    (upper, lowers)
}

/// Scan an OverlayFS `upper_dir` against `lower_dirs` to compute step-level filesystem diffs.
pub fn compute_dir_diff(upper_dir: &Path, lower_dirs: &[PathBuf]) -> Result<Vec<FsDiffEntry>> {
    let mut entries = Vec::new();
    collect_diff_recursive(upper_dir, upper_dir, lower_dirs, &mut entries)?;
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(entries)
}

fn collect_diff_recursive(
    base: &Path,
    dir: &Path,
    lower_dirs: &[PathBuf],
    out: &mut Vec<FsDiffEntry>,
) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let meta = std::fs::symlink_metadata(&path)?;
        let ft = meta.file_type();
        let rel = path.strip_prefix(base).unwrap_or(&path);
        let rel_str = rel.to_string_lossy().to_string();
        let fname = entry.file_name();
        let fname_str = fname.to_string_lossy();

        if fname_str == ".wh..wh..opq" {
            continue;
        }
        if let Some(orig_name) = fname_str.strip_prefix(".wh.") {
            let deleted_rel = match rel.parent() {
                Some(p) if !p.as_os_str().is_empty() => p.join(orig_name),
                _ => PathBuf::from(orig_name),
            };
            out.push(FsDiffEntry {
                path: format!("/{}", deleted_rel.to_string_lossy()),
                kind: DiffKind::Deleted,
                size_bytes: 0,
            });
            continue;
        }
        if ft.is_char_device() {
            let rdev = meta.rdev() as libc::dev_t;
            if libc::major(rdev) == 0 && libc::minor(rdev) == 0 {
                out.push(FsDiffEntry {
                    path: format!("/{rel_str}"),
                    kind: DiffKind::Deleted,
                    size_bytes: 0,
                });
                continue;
            }
        }

        if ft.is_dir() {
            collect_diff_recursive(base, &path, lower_dirs, out)?;
        } else {
            let existed_in_lower = lower_dirs.iter().any(|l| l.join(rel).exists());
            out.push(FsDiffEntry {
                path: format!("/{rel_str}"),
                kind: if existed_in_lower {
                    DiffKind::Modified
                } else {
                    DiffKind::Added
                },
                size_bytes: if ft.is_file() { meta.len() } else { 0 },
            });
        }
    }
    Ok(())
}

fn copy_overlay_upper(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let meta = std::fs::symlink_metadata(&src_path)?;
        let ft = meta.file_type();
        if ft.is_dir() {
            copy_overlay_upper(&src_path, &dst_path)?;
            let _ = std::fs::set_permissions(&dst_path, meta.permissions());
        } else if ft.is_file() {
            std::fs::copy(&src_path, &dst_path)?;
            let _ = std::fs::set_permissions(&dst_path, meta.permissions());
        } else if ft.is_symlink() {
            let target = std::fs::read_link(&src_path)?;
            let _ = std::fs::remove_file(&dst_path);
            std::os::unix::fs::symlink(target, &dst_path)?;
        } else if ft.is_char_device() {
            // Preserve OverlayFS whiteout marker in OCI format if unprivileged mknod fails.
            let rdev = meta.rdev() as libc::dev_t;
            if libc::major(rdev) == 0 && libc::minor(rdev) == 0 {
                if let Some(name) = src_path.file_name().and_then(|n| n.to_str()) {
                    let wh = dst.join(format!(".wh.{name}"));
                    let _ = std::fs::write(wh, b"");
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_dir_diff_detects_added_modified_and_deleted() {
        let base = std::env::temp_dir().join(format!("sbx-diff-test-{}", std::process::id()));
        let lower = base.join("lower");
        let upper = base.join("upper");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(lower.join("workspace")).unwrap();
        std::fs::create_dir_all(upper.join("workspace")).unwrap();

        std::fs::write(lower.join("workspace/existing.txt"), b"old").unwrap();
        std::fs::write(lower.join("workspace/to_delete.txt"), b"bye").unwrap();

        std::fs::write(upper.join("workspace/existing.txt"), b"new-content").unwrap();
        std::fs::write(upper.join("workspace/added.py"), b"print(1)").unwrap();
        std::fs::write(upper.join("workspace/.wh.to_delete.txt"), b"").unwrap();

        let diffs = compute_dir_diff(&upper, &[lower]).unwrap();
        assert_eq!(diffs.len(), 3);
        assert!(diffs
            .iter()
            .any(|d| d.path == "/workspace/added.py" && d.kind == DiffKind::Added));
        assert!(diffs.iter().any(|d| d.path == "/workspace/existing.txt"
            && d.kind == DiffKind::Modified
            && d.size_bytes == 11));
        assert!(diffs
            .iter()
            .any(|d| d.path == "/workspace/to_delete.txt" && d.kind == DiffKind::Deleted));

        let _ = std::fs::remove_dir_all(&base);
    }
}
