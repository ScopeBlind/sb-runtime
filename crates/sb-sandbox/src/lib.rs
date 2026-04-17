//! OS-native sandboxing primitives for `sb-runtime`.
//!
//! # Threat model
//! A sandbox here is a *best-effort* defence-in-depth layer on top of Cedar
//! policy. It's not a complete jail: a determined attacker with kernel
//! exploits can still escape. The goal is to reduce the blast radius of an
//! AI agent that goes off-script — matching the OpenShell model but without
//! Docker / OCI / k3s.
//!
//! # Profile
//! Sandboxes are declarative: callers build a [`Profile`] describing which
//! filesystem paths are readable/writable, which syscalls are allowed, and
//! whether network access is permitted. [`apply`] then installs that profile
//! on the current process before `exec`.
//!
//! # Platform support
//! * **Linux** — Landlock (filesystem) + seccomp-BPF (syscalls). Landlock
//!   requires kernel ≥ 5.13 for basic fs operations and ≥ 6.7 for network
//!   restrictions.
//! * **macOS** — stub. The `sandbox_init`(3) SBPL dialect is private API;
//!   a future version will generate SBPL profiles from [`Profile`] via a
//!   tested helper.
//! * **Windows** — stub. A future version will use Job Objects + AppContainer.
//!
//! On unsupported platforms, [`apply`] returns a clear error so callers can
//! choose to fail-closed (recommended) or proceed with Cedar-only enforcement.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;

pub mod profile;
pub use profile::{NetworkPolicy, Profile, SyscallPolicy};

#[cfg(target_os = "linux")]
mod linux;

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("sandbox not supported on this platform: {0}")]
    Unsupported(&'static str),
    #[error("landlock error: {0}")]
    Landlock(String),
    #[error("seccomp error: {0}")]
    Seccomp(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("profile error: {0}")]
    Profile(String),
}

/// Install the given [`Profile`] on the current process.
///
/// Must be called **before** `execve`. After `apply` returns `Ok`, the
/// current process (and every subsequent child) is confined to the profile.
pub fn apply(profile: &Profile) -> Result<(), SandboxError> {
    #[cfg(target_os = "linux")]
    {
        linux::apply_linux(profile)
    }

    #[cfg(target_os = "macos")]
    {
        let _ = profile;
        Err(SandboxError::Unsupported(
            "macOS sandbox support lands in v0.2; use --allow-unsandboxed to run unconfined",
        ))
    }

    #[cfg(target_os = "windows")]
    {
        let _ = profile;
        Err(SandboxError::Unsupported(
            "Windows sandbox support lands in v0.3; use --allow-unsandboxed to run unconfined",
        ))
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = profile;
        Err(SandboxError::Unsupported("unknown platform"))
    }
}

/// Canonical paths a sandbox likely needs available even for tight profiles
/// (loader, certificates, tmp). Callers can accept or replace these defaults.
#[must_use]
pub fn baseline_read_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/usr"),
        PathBuf::from("/lib"),
        PathBuf::from("/lib64"),
        PathBuf::from("/etc/ssl"),
        PathBuf::from("/etc/resolv.conf"),
    ]
}

/// Reasonable tmp / state dirs a typical sandboxed process needs for write.
#[must_use]
pub fn baseline_write_paths() -> Vec<PathBuf> {
    vec![PathBuf::from("/tmp")]
}

// Re-export for convenience
#[derive(Debug, Serialize, Deserialize)]
pub struct ApplyReport {
    pub platform: String,
    pub landlock: bool,
    pub seccomp: bool,
    pub network: bool,
}
