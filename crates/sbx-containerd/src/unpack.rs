use std::ffi::CString;
use std::fs;
use std::io::{self, Cursor, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use tar::Archive;

struct HashingReader<R: Read> {
    inner: R,
    hasher: Sha256,
}

impl<R: Read> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
        }
    }

    fn finish_digest(self) -> String {
        format!("sha256:{}", hex::encode(self.hasher.finalize()))
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.hasher.update(&buf[..n]);
        }
        Ok(n)
    }
}

/// Compute uncompressed tar `diff_id` (`sha256:...`) without keeping the entire uncompressed tar in memory.
pub fn compute_layer_diff_id(compressed: &[u8], media_type: Option<&str>) -> Result<String> {
    let is_gzip = is_gzip_layer(compressed, media_type);
    let mut reader: Box<dyn Read> = if is_gzip {
        Box::new(GzDecoder::new(Cursor::new(compressed)))
    } else {
        Box::new(Cursor::new(compressed))
    };

    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

/// Compute OCI `chain_id` for a layer given optional parent `chain_id` and layer `diff_id`.
pub fn compute_chain_id(parent_chain_id: Option<&str>, diff_id: &str) -> String {
    match parent_chain_id {
        None => diff_id.to_string(),
        Some(parent) => {
            let mut hasher = Sha256::new();
            hasher.update(parent.as_bytes());
            hasher.update(b" ");
            hasher.update(diff_id.as_bytes());
            format!("sha256:{}", hex::encode(hasher.finalize()))
        }
    }
}

/// Unpack a compressed or uncompressed OCI tar layer into `target_dir` and return its `diff_id`.
pub fn unpack_layer_tar(
    compressed: &[u8],
    media_type: Option<&str>,
    target_dir: &Path,
    lower_dirs: &[PathBuf],
) -> Result<String> {
    fs::create_dir_all(target_dir)
        .with_context(|| format!("failed to create layer dir {}", target_dir.display()))?;

    let is_gzip = is_gzip_layer(compressed, media_type);
    let raw_reader: Box<dyn Read> = if is_gzip {
        Box::new(GzDecoder::new(Cursor::new(compressed)))
    } else {
        Box::new(Cursor::new(compressed))
    };
    let mut hashing_reader = HashingReader::new(raw_reader);

    let is_root = unsafe { libc::geteuid() == 0 };
    let mut deferred_dir_modes: Vec<(PathBuf, u32)> = Vec::new();
    let mut opaque_dirs: Vec<PathBuf> = Vec::new();
    let mut pending_whiteouts: Vec<PathBuf> = Vec::new();

    {
        let mut archive = Archive::new(&mut hashing_reader);
        archive.set_preserve_permissions(true);
        archive.set_preserve_mtime(true);
        archive.set_unpack_xattrs(false);

        for entry_res in archive.entries()? {
            let mut entry = entry_res?;
            let raw_path = entry.path()?.into_owned();
            let rel_path = sanitize_rel_path(&raw_path);
            if rel_path.as_os_str().is_empty() {
                continue;
            }

            let file_name = rel_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default();

            // Handle OCI whiteouts.
            if file_name == ".wh..wh..opq" {
                let dir = match rel_path.parent() {
                    Some(p) if !p.as_os_str().is_empty() => target_dir.join(p),
                    _ => target_dir.to_path_buf(),
                };
                fs::create_dir_all(&dir)?;
                opaque_dirs.push(dir);
                continue;
            }
            if let Some(orig) = file_name.strip_prefix(".wh.") {
                let wh_rel = match rel_path.parent() {
                    Some(p) => p.join(orig),
                    None => PathBuf::from(orig),
                };
                let wh_abs = target_dir.join(&wh_rel);
                if let Some(parent) = wh_abs.parent() {
                    ensure_writable_dir(parent)?;
                }
                if !try_mknod_whiteout(&wh_abs) {
                    pending_whiteouts.push(wh_rel);
                }
                continue;
            }

            let dest = target_dir.join(&rel_path);
            if let Some(parent) = dest.parent() {
                ensure_writable_dir(parent)?;
            }

            let entry_type = entry.header().entry_type();
            let mode = entry.header().mode().unwrap_or(0o755);

            if entry_type.is_dir() {
                if dest.symlink_metadata().is_ok_and(|m| !m.is_dir()) {
                    let _ = fs::remove_file(&dest);
                }
                fs::create_dir_all(&dest)?;
                // Defer restrictive permissions (like 0555) until after child files are extracted.
                fs::set_permissions(&dest, fs::Permissions::from_mode(mode | 0o700))?;
                deferred_dir_modes.push((dest, mode));
                continue;
            }

            // Remove pre-existing non-dir or symlink at destination before extracting.
            if let Ok(meta) = dest.symlink_metadata() {
                if meta.is_dir() {
                    fs::remove_dir_all(&dest)?;
                } else {
                    let _ = fs::remove_file(&dest);
                }
            }

            if entry_type.is_hard_link() {
                if let Some(link_target) = entry.link_name()? {
                    let target_rel = sanitize_rel_path(&link_target);
                    let link_src = target_dir.join(&target_rel);
                    if link_src.exists() {
                        fs::hard_link(&link_src, &dest).with_context(|| {
                            format!(
                                "failed hardlink {} -> {}",
                                dest.display(),
                                link_src.display()
                            )
                        })?;
                        continue;
                    }
                }
            }

            // Skip device nodes when running unprivileged (unless root).
            if (entry_type.is_block_special() || entry_type.is_character_special()) && !is_root {
                continue;
            }

            entry.set_preserve_permissions(true);
            entry.set_preserve_mtime(true);
            entry.unpack_in(target_dir).with_context(|| {
                format!("failed to unpack tar entry {}", rel_path.display())
            })?;
        }
    }

    // Drain any remaining trailing bytes (tar 1024-byte EOF padding) so SHA-256 diff_id is exact.
    let mut drain = [0u8; 4096];
    while hashing_reader.read(&mut drain)? > 0 {}
    let diff_id = hashing_reader.finish_digest();

    // Apply opaque xattrs.
    for dir in opaque_dirs {
        set_overlay_opaque_xattr(&dir, is_root)?;
    }

    // Apply rootless whiteouts via userns overlayfs if any `.wh.<name>` entries existed.
    if !pending_whiteouts.is_empty() {
        apply_rootless_whiteouts(target_dir, lower_dirs, &pending_whiteouts)?;
    }

    // Restore directory modes deepest-first.
    deferred_dir_modes.sort_by(|a, b| b.0.components().count().cmp(&a.0.components().count()));
    for (dir, mode) in deferred_dir_modes {
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(mode));
    }

    Ok(diff_id)
}

fn is_gzip_layer(bytes: &[u8], media_type: Option<&str>) -> bool {
    if bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b {
        return true;
    }
    media_type.is_some_and(|mt| {
        mt.ends_with("+gzip") || mt.ends_with(".tar.gzip") || mt.ends_with(".tar.gz")
    })
}

fn sanitize_rel_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        if let Component::Normal(part) = comp {
            out.push(part);
        }
    }
    out
}

fn ensure_writable_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }
    if let Ok(meta) = fs::symlink_metadata(dir) {
        if meta.is_dir() {
            let mode = meta.permissions().mode();
            if (mode & 0o700) != 0o700 {
                let _ = fs::set_permissions(dir, fs::Permissions::from_mode(mode | 0o700));
            }
        }
    }
    Ok(())
}

fn try_mknod_whiteout(path: &Path) -> bool {
    let Ok(c_path) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    unsafe { libc::mknod(c_path.as_ptr(), libc::S_IFCHR | 0o000, 0) == 0 }
}

fn set_overlay_opaque_xattr(dir: &Path, is_root: bool) -> Result<()> {
    let c_path = CString::new(dir.as_os_str().as_bytes())?;
    let attr_name = if is_root {
        c"trusted.overlay.opaque"
    } else {
        c"user.overlay.opaque"
    };
    let val = b"y";
    let rc = unsafe {
        libc::lsetxattr(
            c_path.as_ptr(),
            attr_name.as_ptr(),
            val.as_ptr().cast(),
            val.len(),
            0,
        )
    };
    if rc != 0 {
        let err = io::Error::last_os_error();
        bail!(
            "failed to set overlay opaque xattr on {}: {err}",
            dir.display()
        );
    }
    Ok(())
}

fn apply_rootless_whiteouts(
    upper_dir: &Path,
    lower_dirs: &[PathBuf],
    whiteouts: &[PathBuf],
) -> Result<()> {
    let work_base = upper_dir
        .parent()
        .unwrap_or(upper_dir)
        .join("sbx-wh-tmp");
    let dummy_lower = work_base.join("lower");
    let work = work_base.join("work");
    let merged = work_base.join("merged");
    fs::create_dir_all(&dummy_lower)?;
    fs::create_dir_all(&work)?;
    fs::create_dir_all(&merged)?;

    let mut lower_str = if lower_dirs.is_empty() {
        dummy_lower.display().to_string()
    } else {
        lower_dirs
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(":")
    };

    // Ensure every whiteout path exists in dummy_lower if lower_dirs is empty so `rm` creates a 0,0 whiteout.
    if lower_dirs.is_empty() {
        for wh in whiteouts {
            let dummy_target = dummy_lower.join(wh);
            if let Some(p) = dummy_target.parent() {
                let _ = fs::create_dir_all(p);
            }
            let _ = fs::write(&dummy_target, b"");
        }
    } else {
        lower_str.push(':');
        lower_str.push_str(&dummy_lower.display().to_string());
        for wh in whiteouts {
            let dummy_target = dummy_lower.join(wh);
            if let Some(p) = dummy_target.parent() {
                let _ = fs::create_dir_all(p);
            }
            let _ = fs::write(&dummy_target, b"");
        }
    }

    let mut script = format!(
        "mount -t overlay overlay -o 'lowerdir={lower_str},upperdir={},workdir={},userxattr' '{}' && ",
        upper_dir.display(),
        work.display(),
        merged.display()
    );
    for wh in whiteouts {
        let target = merged.join(wh);
        script.push_str(&format!("rm -rf '{}' ; ", target.display()));
    }
    script.push_str(&format!("umount '{}'", merged.display()));

    let status = Command::new("unshare")
        .args(["-Urm", "sh", "-c", &script])
        .status()
        .context("failed to invoke unshare for rootless whiteouts")?;

    let _ = fs::remove_dir_all(&work_base);
    if !status.success() {
        bail!("rootless whiteout helper exited with {status}");
    }
    Ok(())
}
