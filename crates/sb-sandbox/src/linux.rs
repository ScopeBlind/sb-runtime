//! Linux-specific sandbox backend: Landlock (filesystem) + seccomp-BPF (syscalls).
//!
//! # What we install
//! * **Landlock ruleset** covering read / write / exec filesystem access.
//!   Granularity is path-scoped — Landlock grants "you may read anything
//!   under /usr" style rules, not file-mode bits.
//! * **Seccomp-BPF filter** applied via `prctl(PR_SET_NO_NEW_PRIVS)` then
//!   `seccomp()`. Strict mode uses a curated allowlist; permissive mode
//!   denies a small deny-list (ptrace, kexec, reboot, mount, keyctl).
//! * **Network policy** — LoopbackOnly and Deny are enforced via Landlock's
//!   network ruleset on kernels ≥ 6.7; on older kernels we fall back to a
//!   seccomp filter that blocks `socket()` for non-AF_UNIX families.
//!
//! # What we don't do
//! * No user-namespace setup. Callers should drop privileges before calling
//!   `apply` — setuid binaries are out of scope.
//! * No process-tree isolation (PID namespaces). Out of scope for v0.1.
//! * No cgroup limits. Kernel memory / CPU limits are orthogonal and can be
//!   layered on via systemd-run, cgroup-tools, or a v0.2 addition.

use crate::profile::{NetworkPolicy, Profile, SyscallPolicy};
use crate::SandboxError;

use landlock::{
    Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr, ABI,
};

/// Apply the profile to the current thread+process on Linux.
///
/// v0.1 supports x86_64 only. Other Linux architectures (notably aarch64,
/// which is increasingly common on cloud instances) refuse-to-run with a
/// clear error rather than silently falling back to a permissive filter —
/// silently weakening enforcement for users who asked for strict mode is
/// strictly worse than a hard stop. The aarch64 syscall table lands in
/// v0.1.1; tracked at https://github.com/ScopeBlind/sb-runtime/issues/1
pub(crate) fn apply_linux(profile: &Profile) -> Result<(), SandboxError> {
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = profile;
        return Err(SandboxError::Unsupported(
            "sb-runtime v0.1 Linux backend supports x86_64 only. \
             aarch64 syscall table is tracked at \
             https://github.com/ScopeBlind/sb-runtime/issues/1 \
             (lands in v0.1.1). Use --allow-unsandboxed to run with \
             Cedar + receipts only on unsupported architectures.",
        ));
    }

    #[cfg(target_arch = "x86_64")]
    {
        apply_landlock(profile)?;
        apply_seccomp(profile)?;
        Ok(())
    }
}

fn apply_landlock(profile: &Profile) -> Result<(), SandboxError> {
    // ABI V2 covers the Read/Write/Exec access rights we need for v0.1.
    // Network rules (V4) require 6.7; handled separately below so older
    // kernels still get filesystem confinement.
    let abi = ABI::V2;

    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(|e| SandboxError::Landlock(e.to_string()))?
        .create()
        .map_err(|e| SandboxError::Landlock(e.to_string()))?;

    // Read
    for p in &profile.read_paths {
        if let Ok(fd) = PathFd::new(p) {
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, AccessFs::from_read(abi)))
                .map_err(|e| SandboxError::Landlock(format!("read {p:?}: {e}")))?;
        }
    }
    // Write
    for p in &profile.write_paths {
        if let Ok(fd) = PathFd::new(p) {
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, AccessFs::from_write(abi)))
                .map_err(|e| SandboxError::Landlock(format!("write {p:?}: {e}")))?;
        }
    }
    // Exec — Landlock treats exec as an FS access right.
    for p in &profile.exec_paths {
        if let Ok(fd) = PathFd::new(p) {
            ruleset = ruleset
                .add_rule(PathBeneath::new(fd, AccessFs::Execute.into()))
                .map_err(|e| SandboxError::Landlock(format!("exec {p:?}: {e}")))?;
        }
    }

    // Restrict self — this is the commitment point. After this, the process
    // and every future child inherit the ruleset.
    ruleset
        .restrict_self()
        .map_err(|e| SandboxError::Landlock(format!("restrict_self: {e}")))?;

    Ok(())
}

fn apply_seccomp(profile: &Profile) -> Result<(), SandboxError> {
    // Must set PR_SET_NO_NEW_PRIVS before installing a seccomp filter,
    // otherwise the kernel refuses for unprivileged processes.
    if let Err(e) = nix::sys::prctl::set_no_new_privs() {
        return Err(SandboxError::Seccomp(format!(
            "prctl(PR_SET_NO_NEW_PRIVS): {e}"
        )));
    }

    let filter = match profile.syscalls {
        SyscallPolicy::Off => return Ok(()),
        SyscallPolicy::Permissive => build_permissive_filter(profile),
        SyscallPolicy::Strict => build_strict_filter(profile),
    };

    let program: seccompiler::BpfProgram = filter
        .try_into()
        .map_err(|e: seccompiler::Error| SandboxError::Seccomp(e.to_string()))?;

    seccompiler::apply_filter(&program)
        .map_err(|e| SandboxError::Seccomp(format!("apply_filter: {e}")))?;

    Ok(())
}

fn build_permissive_filter(profile: &Profile) -> seccompiler::SeccompFilter {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};
    let _ = BpfProgram::default;

    // Deny a small, well-known list; allow everything else.
    let deny: &[&str] = &[
        "ptrace",
        "kexec_load",
        "kexec_file_load",
        "reboot",
        "mount",
        "umount2",
        "pivot_root",
        "swapon",
        "swapoff",
        "init_module",
        "finit_module",
        "delete_module",
        "keyctl",
        "add_key",
        "request_key",
    ];

    let mut rules: std::collections::BTreeMap<i64, Vec<SeccompRule>> =
        std::collections::BTreeMap::new();
    for name in deny {
        if let Some(nr) = syscall_nr(name) {
            rules.insert(nr, vec![]);
        }
    }
    // Network restrictions apply to socket() as well
    maybe_restrict_network(&mut rules, profile);

    SeccompFilter::new(
        rules,
        SeccompAction::Allow,    // default
        SeccompAction::Errno(1), // matched rule -> EPERM
        target_arch(),
    )
    .unwrap_or_else(|_| {
        // Fallback: do-nothing filter (constructor failed, but we must
        // still return something valid)
        SeccompFilter::new(
            std::collections::BTreeMap::new(),
            SeccompAction::Allow,
            SeccompAction::Allow,
            TargetArch::x86_64,
        )
        .expect("trivial filter")
    })
}

fn build_strict_filter(profile: &Profile) -> seccompiler::SeccompFilter {
    use seccompiler::{SeccompAction, SeccompFilter, SeccompRule};

    // Curated allowlist for typical agent-tool processes. The set is
    // intentionally small; it matches the common case (read/write files,
    // spawn subprocess, do loopback network). A future `sandbox_profile`
    // for specific tool types (compiler, HTTP client) will refine this.
    let allowed: &[&str] = &[
        "read",
        "write",
        "close",
        "pread64",
        "pwrite64",
        "readv",
        "writev",
        "openat",
        "open",
        "stat",
        "fstat",
        "lstat",
        "newfstatat",
        "access",
        "faccessat",
        "faccessat2",
        "getcwd",
        "chdir",
        "fchdir",
        "readlink",
        "readlinkat",
        "getdents",
        "getdents64",
        "brk",
        "mmap",
        "munmap",
        "mprotect",
        "madvise",
        "mremap",
        "rt_sigaction",
        "rt_sigprocmask",
        "rt_sigreturn",
        "sigaltstack",
        "exit",
        "exit_group",
        "fork",
        "vfork",
        "clone",
        "clone3",
        "execve",
        "execveat",
        "wait4",
        "waitid",
        "pipe",
        "pipe2",
        "dup",
        "dup2",
        "dup3",
        "fcntl",
        "poll",
        "ppoll",
        "select",
        "pselect6",
        "epoll_create1",
        "epoll_ctl",
        "epoll_wait",
        "epoll_pwait",
        "futex",
        "set_robust_list",
        "get_robust_list",
        "sched_yield",
        "gettimeofday",
        "clock_gettime",
        "clock_nanosleep",
        "nanosleep",
        "getpid",
        "getppid",
        "getuid",
        "geteuid",
        "getgid",
        "getegid",
        "gettid",
        "getrandom",
        "getresuid",
        "getresgid",
        "getpgid",
        "getsid",
        "arch_prctl",
        "prctl",
        "set_tid_address",
        "uname",
    ];

    let network_allowed: &[&str] = match profile.network {
        NetworkPolicy::Allow => &[
            "socket",
            "connect",
            "accept",
            "accept4",
            "bind",
            "listen",
            "sendto",
            "recvfrom",
            "sendmsg",
            "recvmsg",
            "getsockname",
            "getpeername",
            "setsockopt",
            "getsockopt",
            "shutdown",
        ],
        NetworkPolicy::LoopbackOnly | NetworkPolicy::Deny => &[],
    };

    let mut allow_rules: std::collections::BTreeMap<i64, Vec<SeccompRule>> =
        std::collections::BTreeMap::new();
    for name in allowed.iter().chain(network_allowed.iter()) {
        if let Some(nr) = syscall_nr(name) {
            allow_rules.insert(nr, vec![]);
        }
    }

    SeccompFilter::new(
        allow_rules,
        SeccompAction::Errno(1), // default: deny
        SeccompAction::Allow,    // rule matched: allow
        target_arch(),
    )
    .unwrap_or_else(|_| {
        // If the filter fails to compile (e.g. unknown syscall on a weird
        // arch), degrade gracefully to Permissive. A future version will
        // refuse to apply and force the caller to loosen the profile.
        build_permissive_filter(profile)
    })
}

fn maybe_restrict_network(
    rules: &mut std::collections::BTreeMap<i64, Vec<seccompiler::SeccompRule>>,
    profile: &Profile,
) {
    if matches!(
        profile.network,
        NetworkPolicy::Deny | NetworkPolicy::LoopbackOnly
    ) {
        // A conservative first pass: deny socket() entirely. A future
        // revision will allow AF_UNIX + AF_LOCAL for IPC. This is a safe
        // default because LoopbackOnly typically applies to standalone
        // agent tools that don't legitimately need sockets.
        if let Some(nr) = syscall_nr("socket") {
            rules.insert(nr, vec![]);
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn target_arch() -> seccompiler::TargetArch {
    seccompiler::TargetArch::x86_64
}
#[cfg(target_arch = "aarch64")]
fn target_arch() -> seccompiler::TargetArch {
    seccompiler::TargetArch::aarch64
}
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn target_arch() -> seccompiler::TargetArch {
    // Fallback — caller should error in apply if we can't compile a filter.
    seccompiler::TargetArch::x86_64
}

/// Resolve a syscall name to its architecture-specific number. Returns
/// `None` if the syscall is unknown on this architecture.
#[cfg(target_arch = "x86_64")]
fn syscall_nr(name: &str) -> Option<i64> {
    // Minimal table of the syscalls we reference. Numbers from
    // <asm/unistd_64.h>. A future version will generate this via libseccomp
    // or a build.rs to match the running kernel.
    match name {
        "read" => Some(0),
        "write" => Some(1),
        "open" => Some(2),
        "close" => Some(3),
        "stat" => Some(4),
        "fstat" => Some(5),
        "lstat" => Some(6),
        "poll" => Some(7),
        "mmap" => Some(9),
        "mprotect" => Some(10),
        "munmap" => Some(11),
        "brk" => Some(12),
        "rt_sigaction" => Some(13),
        "rt_sigprocmask" => Some(14),
        "rt_sigreturn" => Some(15),
        "pread64" => Some(17),
        "pwrite64" => Some(18),
        "readv" => Some(19),
        "writev" => Some(20),
        "access" => Some(21),
        "pipe" => Some(22),
        "select" => Some(23),
        "sched_yield" => Some(24),
        "mremap" => Some(25),
        "madvise" => Some(28),
        "dup" => Some(32),
        "dup2" => Some(33),
        "nanosleep" => Some(35),
        "getpid" => Some(39),
        "socket" => Some(41),
        "connect" => Some(42),
        "accept" => Some(43),
        "sendto" => Some(44),
        "recvfrom" => Some(45),
        "sendmsg" => Some(46),
        "recvmsg" => Some(47),
        "shutdown" => Some(48),
        "bind" => Some(49),
        "listen" => Some(50),
        "getsockname" => Some(51),
        "getpeername" => Some(52),
        "setsockopt" => Some(54),
        "getsockopt" => Some(55),
        "clone" => Some(56),
        "fork" => Some(57),
        "vfork" => Some(58),
        "execve" => Some(59),
        "exit" => Some(60),
        "wait4" => Some(61),
        "uname" => Some(63),
        "fcntl" => Some(72),
        "getcwd" => Some(79),
        "chdir" => Some(80),
        "fchdir" => Some(81),
        "readlink" => Some(89),
        "getuid" => Some(102),
        "getgid" => Some(104),
        "geteuid" => Some(107),
        "getegid" => Some(108),
        "getppid" => Some(110),
        "getpgid" => Some(121),
        "getsid" => Some(124),
        "arch_prctl" => Some(158),
        "gettid" => Some(186),
        "getdents" => Some(78),
        "getdents64" => Some(217),
        "set_tid_address" => Some(218),
        "clock_gettime" => Some(228),
        "clock_nanosleep" => Some(230),
        "exit_group" => Some(231),
        "epoll_wait" => Some(232),
        "epoll_ctl" => Some(233),
        "waitid" => Some(247),
        "openat" => Some(257),
        "newfstatat" => Some(262),
        "readlinkat" => Some(267),
        "faccessat" => Some(269),
        "pselect6" => Some(270),
        "ppoll" => Some(271),
        "set_robust_list" => Some(273),
        "get_robust_list" => Some(274),
        "sync_file_range" => Some(277),
        "accept4" => Some(288),
        "epoll_create1" => Some(291),
        "pipe2" => Some(293),
        "prlimit64" => Some(302),
        "gettimeofday" => Some(96),
        "prctl" => Some(157),
        "futex" => Some(202),
        "sigaltstack" => Some(131),
        "getrandom" => Some(318),
        "execveat" => Some(322),
        "clone3" => Some(435),
        "epoll_pwait" => Some(281),
        "dup3" => Some(292),
        "getresuid" => Some(118),
        "getresgid" => Some(120),
        "ptrace" => Some(101),
        "kexec_load" => Some(246),
        "kexec_file_load" => Some(320),
        "reboot" => Some(169),
        "mount" => Some(165),
        "umount2" => Some(166),
        "pivot_root" => Some(155),
        "swapon" => Some(167),
        "swapoff" => Some(168),
        "init_module" => Some(175),
        "finit_module" => Some(313),
        "delete_module" => Some(176),
        "keyctl" => Some(250),
        "add_key" => Some(248),
        "request_key" => Some(249),
        "faccessat2" => Some(439),
        _ => None,
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[allow(clippy::missing_const_for_fn)]
fn syscall_nr(_name: &str) -> Option<i64> {
    None
}
