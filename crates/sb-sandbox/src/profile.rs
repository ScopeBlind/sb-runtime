//! The declarative sandbox profile.
//!
//! A `Profile` is a platform-independent description of what a sandboxed
//! process is allowed to do. Each backend (Linux Landlock+seccomp, macOS
//! SBPL, Windows Job Objects) translates it into native primitives.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// What a sandboxed process may do with the network.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    /// Loopback-only. Most restrictive default for tool-use agents that
    /// only need to talk to a local policy evaluator or debugger.
    LoopbackOnly,
    /// Deny all network I/O. Suitable for pure file-transform workloads.
    Deny,
    /// Allow all network I/O. Use only when the policy *explicitly* permits
    /// it — this defeats the sandbox's network layer.
    Allow,
}

/// What syscalls the sandbox permits. "Strict" is a curated seccomp-BPF
/// allowlist suitable for most agent tools; "Permissive" only blocks the
/// demonstrably-dangerous ones (useful for debugging / CI); "Off" means
/// no syscall filtering (Cedar-only enforcement).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SyscallPolicy {
    Strict,
    Permissive,
    Off,
}

/// Platform-independent sandbox profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    /// Paths allowed for *read* (open / stat / readlink / list).
    #[serde(default)]
    pub read_paths: Vec<PathBuf>,
    /// Paths allowed for *write* (create / truncate / unlink).
    #[serde(default)]
    pub write_paths: Vec<PathBuf>,
    /// Paths allowed for *exec*.
    #[serde(default)]
    pub exec_paths: Vec<PathBuf>,
    /// Network policy.
    #[serde(default = "default_network")]
    pub network: NetworkPolicy,
    /// Syscall policy.
    #[serde(default = "default_syscalls")]
    pub syscalls: SyscallPolicy,
    /// Hostname the sandboxed process should see (if supported). `None` =
    /// inherit. Useful for reproducible CI.
    #[serde(default)]
    pub hostname: Option<String>,
}

fn default_network() -> NetworkPolicy {
    NetworkPolicy::LoopbackOnly
}
fn default_syscalls() -> SyscallPolicy {
    SyscallPolicy::Strict
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            read_paths: Vec::new(),
            write_paths: Vec::new(),
            exec_paths: Vec::new(),
            network: NetworkPolicy::LoopbackOnly,
            syscalls: SyscallPolicy::Strict,
            hostname: None,
        }
    }
}

impl Profile {
    /// Minimal profile for running a read-only transform (e.g. parse files,
    /// emit to stdout). Reads /usr /lib /etc/ssl; no writes outside /tmp;
    /// no network; strict seccomp.
    #[must_use]
    pub fn read_only_transform() -> Self {
        Self {
            read_paths: crate::baseline_read_paths(),
            write_paths: crate::baseline_write_paths(),
            exec_paths: vec![PathBuf::from("/usr")],
            network: NetworkPolicy::Deny,
            syscalls: SyscallPolicy::Strict,
            hostname: None,
        }
    }

    /// Developer profile: fairly permissive, suitable for running a coding
    /// agent on your laptop. Reads/writes your workspace; loopback network
    /// only.
    #[must_use]
    pub fn dev(workspace: PathBuf) -> Self {
        let mut read = crate::baseline_read_paths();
        read.push(workspace.clone());
        Self {
            read_paths: read,
            write_paths: vec![PathBuf::from("/tmp"), workspace],
            exec_paths: vec![PathBuf::from("/usr"), PathBuf::from("/bin")],
            network: NetworkPolicy::LoopbackOnly,
            syscalls: SyscallPolicy::Permissive,
            hostname: None,
        }
    }

    /// Load a profile from a JSON file.
    pub fn from_json_file(path: impl AsRef<std::path::Path>) -> Result<Self, crate::SandboxError> {
        let data = std::fs::read_to_string(path)?;
        serde_json::from_str(&data).map_err(|e| crate::SandboxError::Profile(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_conservative() {
        let p = Profile::default();
        assert_eq!(p.network, NetworkPolicy::LoopbackOnly);
        assert_eq!(p.syscalls, SyscallPolicy::Strict);
        assert!(p.read_paths.is_empty());
    }

    #[test]
    fn read_only_transform_has_sensible_shape() {
        let p = Profile::read_only_transform();
        assert_eq!(p.network, NetworkPolicy::Deny);
        assert!(!p.read_paths.is_empty());
        assert!(p.write_paths.iter().any(|w| w.ends_with("tmp")));
    }

    #[test]
    fn dev_includes_workspace() {
        let ws = PathBuf::from("/home/alice/code");
        let p = Profile::dev(ws.clone());
        assert!(p.read_paths.contains(&ws));
        assert!(p.write_paths.contains(&ws));
    }

    #[test]
    fn json_roundtrip() {
        let p = Profile::read_only_transform();
        let s = serde_json::to_string(&p).unwrap();
        let p2: Profile = serde_json::from_str(&s).unwrap();
        assert_eq!(p.network, p2.network);
        assert_eq!(p.syscalls, p2.syscalls);
    }
}
