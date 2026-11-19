#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Frame magic bytes: 0x5342 ("SB").
pub const FRAME_MAGIC: u16 = 0x5342;
/// Wire protocol version.
pub const FRAME_VERSION: u8 = 1;
/// Fixed header size in bytes.
pub const HEADER_LEN: usize = 16;
/// Maximum allowed frame payload size (16 MiB).
pub const MAX_PAYLOAD_LEN: u32 = 16 * 1024 * 1024;

/// Default frame flags.
pub const FLAG_NONE: u8 = 0x00;
/// Flag set on OP_PING responses (OP_PONG).
pub const FLAG_PONG: u8 = 0x01;
/// Flag indicating end-of-stream on data frames.
pub const FLAG_EOF: u8 = 0x02;

/// Protocol encoding/decoding errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtoError {
    #[error("invalid frame magic: expected 0x{expected:04x}, got 0x{actual:04x}")]
    InvalidMagic { expected: u16, actual: u16 },
    #[error("unsupported frame version: expected {expected}, got {actual}")]
    UnsupportedVersion { expected: u8, actual: u8 },
    #[error("unknown opcode: 0x{0:02x}")]
    UnknownOpCode(u8),
    #[error("payload length {0} exceeds maximum {MAX_PAYLOAD_LEN}")]
    PayloadTooLarge(u32),
    #[error("output buffer too small: need at least {needed} bytes, got {actual}")]
    BufferTooSmall { needed: usize, actual: usize },
    #[error("postcard serialization error")]
    SerializeError,
    #[error("postcard deserialization error")]
    DeserializeError,
}

/// Host <-> Guest binary frame OpCodes (docs/ARCHITECTURE.md Section 4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpCode {
    Ping = 0x01,
    ExecReq = 0x02,
    StdinData = 0x03,
    StdoutData = 0x04,
    StderrData = 0x05,
    ExecExit = 0x06,
    Signal = 0x07,
    FilePut = 0x08,
    FileGet = 0x09,
    Freeze = 0x0A,
    Thaw = 0x0B,
    ReplExec = 0x0C,
}

impl OpCode {
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for OpCode {
    type Error = ProtoError;

    #[inline]
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::Ping),
            0x02 => Ok(Self::ExecReq),
            0x03 => Ok(Self::StdinData),
            0x04 => Ok(Self::StdoutData),
            0x05 => Ok(Self::StderrData),
            0x06 => Ok(Self::ExecExit),
            0x07 => Ok(Self::Signal),
            0x08 => Ok(Self::FilePut),
            0x09 => Ok(Self::FileGet),
            0x0A => Ok(Self::Freeze),
            0x0B => Ok(Self::Thaw),
            0x0C => Ok(Self::ReplExec),
            other => Err(ProtoError::UnknownOpCode(other)),
        }
    }
}

/// 16-byte fixed header for Host <-> Guest vsock/Unix-socket frames.
///
/// Layout (big-endian network order):
/// - bytes 0..2: `magic` (`0x5342`)
/// - byte 2: `version` (`1`)
/// - byte 3: `opcode` (`OpCode`)
/// - bytes 4..8: `request_id` (`u32`)
/// - bytes 8..12: `payload_len` (`u32`)
/// - byte 12: `flags` (`u8`)
/// - bytes 13..16: `reserved` (`[u8; 3]`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VsockFrameHeader {
    pub magic: u16,
    pub version: u8,
    pub opcode: OpCode,
    pub request_id: u32,
    pub payload_len: u32,
    pub flags: u8,
    pub reserved: [u8; 3],
}

impl VsockFrameHeader {
    #[inline]
    pub const fn new(opcode: OpCode, request_id: u32, payload_len: u32, flags: u8) -> Self {
        Self {
            magic: FRAME_MAGIC,
            version: FRAME_VERSION,
            opcode,
            request_id,
            payload_len,
            flags,
            reserved: [0; 3],
        }
    }

    #[inline]
    pub fn write_to(&self, buf: &mut [u8; HEADER_LEN]) {
        let magic = self.magic.to_be_bytes();
        let req_id = self.request_id.to_be_bytes();
        let len = self.payload_len.to_be_bytes();
        buf[0] = magic[0];
        buf[1] = magic[1];
        buf[2] = self.version;
        buf[3] = self.opcode.as_u8();
        buf[4..8].copy_from_slice(&req_id);
        buf[8..12].copy_from_slice(&len);
        buf[12] = self.flags;
        buf[13..16].copy_from_slice(&self.reserved);
    }

    #[inline]
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        self.write_to(&mut buf);
        buf
    }

    #[inline]
    pub fn from_bytes(buf: &[u8; HEADER_LEN]) -> Result<Self, ProtoError> {
        let magic = u16::from_be_bytes([buf[0], buf[1]]);
        if magic != FRAME_MAGIC {
            return Err(ProtoError::InvalidMagic {
                expected: FRAME_MAGIC,
                actual: magic,
            });
        }
        let version = buf[2];
        if version != FRAME_VERSION {
            return Err(ProtoError::UnsupportedVersion {
                expected: FRAME_VERSION,
                actual: version,
            });
        }
        let opcode = OpCode::try_from(buf[3])?;
        let request_id = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let payload_len = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(ProtoError::PayloadTooLarge(payload_len));
        }
        let flags = buf[12];
        let reserved = [buf[13], buf[14], buf[15]];
        Ok(Self {
            magic,
            version,
            opcode,
            request_id,
            payload_len,
            flags,
            reserved,
        })
    }
}

/// Zero-heap-allocation encoder that serializes `payload` via `postcard` directly into
/// `out_buf[HEADER_LEN..]` and writes the 16-byte `VsockFrameHeader` into `out_buf[..HEADER_LEN]`.
pub fn encode_postcard_frame<T: Serialize>(
    opcode: OpCode,
    request_id: u32,
    flags: u8,
    payload: &T,
    out_buf: &mut [u8],
) -> Result<usize, ProtoError> {
    if out_buf.len() < HEADER_LEN {
        return Err(ProtoError::BufferTooSmall {
            needed: HEADER_LEN,
            actual: out_buf.len(),
        });
    }

    let written = postcard::to_slice(payload, &mut out_buf[HEADER_LEN..])
        .map_err(|_| ProtoError::SerializeError)?
        .len();

    let payload_len = u32::try_from(written).map_err(|_| ProtoError::PayloadTooLarge(u32::MAX))?;
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(ProtoError::PayloadTooLarge(payload_len));
    }

    let out_len = out_buf.len();
    let header = VsockFrameHeader::new(opcode, request_id, payload_len, flags);
    let hdr_slice: &mut [u8; HEADER_LEN] = (&mut out_buf[..HEADER_LEN])
        .try_into()
        .map_err(|_| ProtoError::BufferTooSmall {
            needed: HEADER_LEN,
            actual: out_len,
        })?;
    header.write_to(hdr_slice);

    Ok(HEADER_LEN + written)
}

/// Zero-heap-allocation encoder for raw byte payloads (e.g., stdout/stderr/stdin chunks).
pub fn encode_raw_frame(
    opcode: OpCode,
    request_id: u32,
    flags: u8,
    payload: &[u8],
    out_buf: &mut [u8],
) -> Result<usize, ProtoError> {
    let payload_len =
        u32::try_from(payload.len()).map_err(|_| ProtoError::PayloadTooLarge(u32::MAX))?;
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(ProtoError::PayloadTooLarge(payload_len));
    }
    let total = HEADER_LEN + payload.len();
    if out_buf.len() < total {
        return Err(ProtoError::BufferTooSmall {
            needed: total,
            actual: out_buf.len(),
        });
    }
    let out_len = out_buf.len();
    let header = VsockFrameHeader::new(opcode, request_id, payload_len, flags);
    let hdr_slice: &mut [u8; HEADER_LEN] = (&mut out_buf[..HEADER_LEN])
        .try_into()
        .map_err(|_| ProtoError::BufferTooSmall {
            needed: HEADER_LEN,
            actual: out_len,
        })?;
    header.write_to(hdr_slice);
    out_buf[HEADER_LEN..total].copy_from_slice(payload);
    Ok(total)
}

/// Deserialize a postcard payload slice.
#[inline]
pub fn decode_postcard_payload<'a, T: Deserialize<'a>>(payload: &'a [u8]) -> Result<T, ProtoError> {
    postcard::from_bytes(payload).map_err(|_| ProtoError::DeserializeError)
}

/// Ping request payload (`OpCode::Ping`, `flags = FLAG_NONE`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PingPayload {
    pub timestamp_ns: u64,
    pub agent_pid: u32,
}

/// Pong response payload (`OpCode::Ping`, `flags = FLAG_PONG`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PongPayload {
    pub timestamp_ns: u64,
    pub agent_pid: u32,
}

/// Command execution request (`OpCode::ExecReq`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecRequest {
    pub argv: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: Option<String>,
    pub timeout_ms: u64,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub tty: bool,
}

/// Command completion summary (`OpCode::ExecExit`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecExitPayload {
    pub exit_code: i32,
    pub term_signal: Option<i32>,
    pub user_cpu_us: u64,
    pub sys_cpu_us: u64,
    pub max_rss_kb: u64,
    pub elapsed_us: u64,
    pub error: Option<String>,
}

/// POSIX signal delivery request (`OpCode::Signal`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignalRequest {
    pub target_request_id: u32,
    pub signal: i32,
}

/// Host -> Guest file upload request (`OpCode::FilePut`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilePutRequest {
    pub path: String,
    pub mode: u32,
    pub data: Vec<u8>,
}

/// Guest -> Host file upload acknowledgement (`OpCode::FilePut`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilePutResponse {
    pub ok: bool,
    pub bytes_written: u64,
    pub error: Option<String>,
}

/// Host -> Guest file download request (`OpCode::FileGet`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileGetRequest {
    pub path: String,
    pub max_bytes: u64,
}

/// Guest -> Host file download response (`OpCode::FileGet`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileGetResponse {
    pub ok: bool,
    pub mode: u32,
    pub data: Vec<u8>,
    pub error: Option<String>,
}

/// Host -> Guest stateful REPL execution request (`OpCode::ReplExec`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplExecRequest {
    pub language: String,
    pub code: String,
    pub timeout_ms: u64,
}

/// Guest -> Host stateful REPL execution response (`OpCode::ReplExec`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplExecResponse {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub elapsed_us: u64,
    pub error: Option<String>,
}

/// Unique sandbox identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SandboxId(pub String);

impl SandboxId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SandboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for SandboxId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<String> for SandboxId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for SandboxId {
    fn from(value: &str) -> Self {
        Self(String::from(value))
    }
}

/// Sandbox lifecycle state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxState {
    Creating,
    Warm,
    Running,
    Sleeping,
    Snapshotted,
    Destroyed,
}

/// Isolation driver backend selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum BackendKind {
    #[default]
    Native,
    Gvisor,
    MicroVm,
}

/// Seccomp filtering strictness level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SeccompMode {
    Strict,
    #[default]
    Standard,
    Custom,
}

/// Sandbox network isolation policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum NetworkPolicy {
    #[default]
    Disabled,
    AllowlistProxy {
        allowed_hosts: Vec<String>,
        block_private_cidrs: bool,
    },
}

/// Zero-Trust Secret Injection Rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRule {
    pub placeholder: String,
    pub allowed_hosts: Vec<String>,
    pub header_name: String,
    pub secret_ref: String,
}

/// Immutable per-sandbox security and resource policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityPolicy {
    pub backend: BackendKind,
    pub cpu_cores: f32,
    pub cpu_quota_us: u64,
    pub memory_limit_mb: u64,
    pub pids_limit: u32,
    pub disk_quota_mb: u64,
    pub readonly_rootfs: bool,
    pub seccomp_mode: SeccompMode,
    pub writable_paths: Vec<String>,
    pub network: NetworkPolicy,
    pub secret_bindings: Vec<SecretRule>,
    pub max_ttl_sec: u64,
    pub idle_sleep_sec: u64,
    pub auto_destroy: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            backend: BackendKind::Native,
            cpu_cores: 2.0,
            cpu_quota_us: 200_000, // 200ms per 100ms period = 2 vCPU
            memory_limit_mb: 1024,
            pids_limit: 128,
            disk_quota_mb: 2048,
            readonly_rootfs: false,
            seccomp_mode: SeccompMode::Standard,
            writable_paths: alloc::vec![String::from("/workspace"), String::from("/tmp")],
            network: NetworkPolicy::Disabled,
            secret_bindings: Vec::new(),
            max_ttl_sec: 3600,
            idle_sleep_sec: 300,
            auto_destroy: true,
        }
    }
}

/// Specification required to instantiate a sandbox.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SandboxSpec {
    pub id: SandboxId,
    pub image: String,
    pub policy: SecurityPolicy,
    pub env: Vec<(String, String)>,
    pub workdir: Option<String>,
}

/// Step-level snapshot metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotMeta {
    pub id: String,
    pub sandbox_id: SandboxId,
    pub parent_id: Option<String>,
    pub label: Option<String>,
    pub created_at_unix: u64,
}

/// Type of filesystem modification detected in a sandbox layer diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffKind {
    Added,
    Modified,
    Deleted,
}

/// Single entry in a sandbox filesystem diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsDiffEntry {
    pub path: String,
    pub kind: DiffKind,
    pub size_bytes: u64,
}

/// Memory + filesystem checkpoint metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointMeta {
    pub id: String,
    pub sandbox_id: SandboxId,
    pub image: String,
    pub snapshot_id: String,
    pub created_at_unix: u64,
    pub has_repl_state: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trip_zero_alloc() {
        let hdr = VsockFrameHeader::new(OpCode::ExecReq, 42, 128, FLAG_EOF);
        let bytes = hdr.to_bytes();
        let decoded = VsockFrameHeader::from_bytes(&bytes).expect("header should decode");
        assert_eq!(decoded, hdr);
    }

    #[test]
    fn header_rejects_bad_magic_and_version() {
        let mut bytes = VsockFrameHeader::new(OpCode::Ping, 1, 0, FLAG_NONE).to_bytes();
        bytes[0] = 0x00;
        assert!(matches!(
            VsockFrameHeader::from_bytes(&bytes),
            Err(ProtoError::InvalidMagic { .. })
        ));

        let mut bytes = VsockFrameHeader::new(OpCode::Ping, 1, 0, FLAG_NONE).to_bytes();
        bytes[2] = 99;
        assert!(matches!(
            VsockFrameHeader::from_bytes(&bytes),
            Err(ProtoError::UnsupportedVersion { .. })
        ));
    }

    #[test]
    fn postcard_frame_round_trip() {
        let req = ExecRequest {
            argv: alloc::vec![String::from("/bin/echo"), String::from("hello")],
            env: alloc::vec![(String::from("FOO"), String::from("bar"))],
            cwd: Some(String::from("/workspace")),
            timeout_ms: 5000,
            uid: Some(1000),
            gid: Some(1000),
            tty: false,
        };
        let mut buf = [0u8; 512];
        let total_len =
            encode_postcard_frame(OpCode::ExecReq, 7, FLAG_NONE, &req, &mut buf).expect("encode");

        let hdr_bytes: &[u8; HEADER_LEN] = buf[..HEADER_LEN].try_into().unwrap();
        let hdr = VsockFrameHeader::from_bytes(hdr_bytes).expect("decode header");
        assert_eq!(hdr.opcode, OpCode::ExecReq);
        assert_eq!(hdr.request_id, 7);
        assert_eq!(hdr.payload_len as usize, total_len - HEADER_LEN);

        let decoded: ExecRequest =
            decode_postcard_payload(&buf[HEADER_LEN..total_len]).expect("decode payload");
        assert_eq!(decoded, req);
    }

    #[test]
    fn exec_exit_payload_round_trip() {
        let exit = ExecExitPayload {
            exit_code: 0,
            term_signal: None,
            user_cpu_us: 1200,
            sys_cpu_us: 450,
            max_rss_kb: 4096,
            elapsed_us: 2300,
            error: None,
        };
        let mut buf = [0u8; 256];
        let total =
            encode_postcard_frame(OpCode::ExecExit, 9, FLAG_NONE, &exit, &mut buf).expect("encode");
        let decoded: ExecExitPayload =
            decode_postcard_payload(&buf[HEADER_LEN..total]).expect("decode");
        assert_eq!(decoded, exit);
    }

    #[test]
    fn file_transfer_payloads_round_trip() {
        let put_req = FilePutRequest {
            path: String::from("/workspace/hello.py"),
            mode: 0o644,
            data: alloc::vec![1, 2, 3, 4],
        };
        let mut buf = [0u8; 256];
        let total =
            encode_postcard_frame(OpCode::FilePut, 10, FLAG_NONE, &put_req, &mut buf).expect("encode");
        let hdr = VsockFrameHeader::from_bytes(buf[..HEADER_LEN].try_into().unwrap()).unwrap();
        assert_eq!(hdr.opcode, OpCode::FilePut);
        let decoded_put: FilePutRequest =
            decode_postcard_payload(&buf[HEADER_LEN..total]).expect("decode");
        assert_eq!(decoded_put, put_req);

        let put_resp = FilePutResponse {
            ok: true,
            bytes_written: 4,
            error: None,
        };
        let total =
            encode_postcard_frame(OpCode::FilePut, 10, FLAG_PONG, &put_resp, &mut buf).expect("encode");
        let decoded_put_resp: FilePutResponse =
            decode_postcard_payload(&buf[HEADER_LEN..total]).expect("decode");
        assert_eq!(decoded_put_resp, put_resp);

        let get_req = FileGetRequest {
            path: String::from("/workspace/hello.py"),
            max_bytes: 1024,
        };
        let total =
            encode_postcard_frame(OpCode::FileGet, 11, FLAG_NONE, &get_req, &mut buf).expect("encode");
        let decoded_get: FileGetRequest =
            decode_postcard_payload(&buf[HEADER_LEN..total]).expect("decode");
        assert_eq!(decoded_get, get_req);

        let get_resp = FileGetResponse {
            ok: true,
            mode: 0o644,
            data: alloc::vec![1, 2, 3, 4],
            error: None,
        };
        let total =
            encode_postcard_frame(OpCode::FileGet, 11, FLAG_PONG, &get_resp, &mut buf).expect("encode");
        let decoded_get_resp: FileGetResponse =
            decode_postcard_payload(&buf[HEADER_LEN..total]).expect("decode");
        assert_eq!(decoded_get_resp, get_resp);
    }

    #[test]
    fn repl_exec_payloads_round_trip() {
        let req = ReplExecRequest {
            language: String::from("python"),
            code: String::from("x = 40 + 2\nx"),
            timeout_ms: 5000,
        };
        let mut buf = [0u8; 512];
        let total =
            encode_postcard_frame(OpCode::ReplExec, 12, FLAG_NONE, &req, &mut buf).expect("encode");
        let hdr = VsockFrameHeader::from_bytes(buf[..HEADER_LEN].try_into().unwrap()).unwrap();
        assert_eq!(hdr.opcode, OpCode::ReplExec);
        let decoded_req: ReplExecRequest =
            decode_postcard_payload(&buf[HEADER_LEN..total]).expect("decode");
        assert_eq!(decoded_req, req);

        let resp = ReplExecResponse {
            exit_code: 0,
            stdout: String::from("42\n"),
            stderr: String::new(),
            elapsed_us: 350,
            error: None,
        };
        let total =
            encode_postcard_frame(OpCode::ReplExec, 12, FLAG_PONG, &resp, &mut buf).expect("encode");
        let decoded_resp: ReplExecResponse =
            decode_postcard_payload(&buf[HEADER_LEN..total]).expect("decode");
        assert_eq!(decoded_resp, resp);
    }
}
