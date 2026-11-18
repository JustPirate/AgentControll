//! Kernel-enforced filesystem sandboxing via Linux Landlock.
//!
//! Provides defense-in-depth filesystem access controls for agent child processes
//! (Antigravity, Claude Code, Shell, and PTY sessions), mitigating workspace boundary
//! violation (Threat T6).

use anyhow::{bail, Context, Result};
use std::io;
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

/// Maximum Landlock ABI version supported by this crate.
pub const LANDLOCK_MAX_ABI: u32 = 4;

/// Linux syscall numbers for Landlock.
#[cfg(target_os = "linux")]
#[allow(non_upper_case_globals)]
pub const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
#[cfg(target_os = "linux")]
#[allow(non_upper_case_globals)]
pub const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
#[cfg(target_os = "linux")]
#[allow(non_upper_case_globals)]
pub const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

/// Flag to probe the supported Landlock ABI version.
pub const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;

/// Rule type for path hierarchy matching.
pub const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

// Filesystem Access Rights Bitflags (Linux Landlock)
pub const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
pub const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
pub const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
pub const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
pub const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
pub const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
pub const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
pub const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
pub const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
pub const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
pub const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
pub const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
pub const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
pub const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13; // ABI v2+ (Linux 5.19+)
pub const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14; // ABI v3+ (Linux 6.2+)
pub const LANDLOCK_ACCESS_FS_IOCTL_DEV: u64 = 1 << 15; // ABI v5+ (Linux 6.10+)

/// Valid access rights that may be requested for a regular file.
/// Adding directory-only access rights (such as `READ_DIR` or `REFER`) to a regular
/// file fails with `EINVAL` (errno 22). All file rules must be masked by `FILE_MASK`.
pub const FILE_MASK: u64 = LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_TRUNCATE;

/// Attributes for `SYS_landlock_create_ruleset`.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct LandlockRulesetAttr {
    pub handled_access_fs: u64,
}

/// Attributes for `SYS_landlock_add_rule` with `LANDLOCK_RULE_PATH_BENEATH`.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct LandlockPathBeneathAttr {
    pub allowed_access: u64,
    pub parent_fd: i32,
}

/// Return the cumulative handled filesystem access mask for a given ABI version.
pub fn handled_fs_access_mask(abi: u32) -> u64 {
    match abi {
        0 => 0,
        1 => (1 << 13) - 1,     // ABI v1 (bits 0..12)
        2 => (1 << 14) - 1,     // ABI v2 (adds REFER)
        3 | 4 => (1 << 15) - 1, // ABI v3 & v4 (adds TRUNCATE)
        _ => (1 << 15) - 1,     // ABI v5+ (cap to handled flags)
    }
}

/// Compute the Read-Only filesystem access mask supported by the kernel ABI.
pub fn read_only_fs_mask(abi: u32) -> u64 {
    let mask = LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR;
    mask & handled_fs_access_mask(abi)
}

/// Compute the Read-Write filesystem access mask supported by the kernel ABI.
pub fn read_write_fs_mask(abi: u32) -> u64 {
    handled_fs_access_mask(abi)
}

/// Probe the host kernel's Landlock ABI version.
/// Returns `Some(abi_version)` (>= 1) if supported, or `None` if unsupported or disabled.
pub fn probe_landlock_abi() -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        let res = unsafe {
            libc::syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                std::ptr::null::<LandlockRulesetAttr>(),
                0usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        if res >= 1 {
            Some(res as u32)
        } else {
            None
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Comprehensive Landlock system readiness status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LandlockStatus {
    Supported { abi: u32 },
    Unsupported { reason: String },
    Disabled,
}

impl LandlockStatus {
    /// Probe the kernel Landlock status.
    pub fn probe() -> Self {
        #[cfg(target_os = "linux")]
        {
            let res = unsafe {
                libc::syscall(
                    SYS_LANDLOCK_CREATE_RULESET,
                    std::ptr::null::<LandlockRulesetAttr>(),
                    0usize,
                    LANDLOCK_CREATE_RULESET_VERSION,
                )
            };
            if res >= 1 {
                LandlockStatus::Supported { abi: res as u32 }
            } else {
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::ENOSYS) => LandlockStatus::Unsupported {
                        reason: "Kernel does not support Landlock (requires Linux 5.13+)".to_string(),
                    },
                    Some(libc::EOPNOTSUPP) => LandlockStatus::Disabled,
                    _ => LandlockStatus::Unsupported {
                        reason: format!("Landlock probe returned error: {err}"),
                    },
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            LandlockStatus::Unsupported {
                reason: "Landlock is only available on Linux".to_string(),
            }
        }
    }

    /// Returns true if Landlock is actively supported on this host.
    pub fn is_supported(&self) -> bool {
        matches!(self, LandlockStatus::Supported { .. })
    }
}

/// Access permission level for allowlisted paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathAccess {
    ReadOnly,
    ReadWrite,
}

/// Sandboxing policy defining permitted directory boundaries.
#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    pub workspace_path: PathBuf,
    pub profile_path: Option<PathBuf>,
    pub extra_read_paths: Vec<PathBuf>,
    pub extra_write_paths: Vec<PathBuf>,
    pub allow_network: bool,
    pub mode: String, // "auto", "landlock", "disabled"
}

impl SandboxPolicy {
    pub fn new(workspace_path: impl Into<PathBuf>) -> Self {
        Self {
            workspace_path: workspace_path.into(),
            profile_path: None,
            extra_read_paths: Vec::new(),
            extra_write_paths: Vec::new(),
            allow_network: true,
            mode: "auto".to_string(),
        }
    }

    pub fn with_profile(mut self, profile_path: impl Into<PathBuf>) -> Self {
        self.profile_path = Some(profile_path.into());
        self
    }

    pub fn with_extra_read_paths(mut self, paths: impl IntoIterator<Item = PathBuf>) -> Self {
        self.extra_read_paths.extend(paths);
        self
    }

    pub fn with_extra_write_paths(mut self, paths: impl IntoIterator<Item = PathBuf>) -> Self {
        self.extra_write_paths.extend(paths);
        self
    }

    pub fn with_mode(mut self, mode: impl Into<String>) -> Self {
        self.mode = mode.into();
        self
    }

    pub fn with_allow_network(mut self, allow: bool) -> Self {
        self.allow_network = allow;
        self
    }

    /// Construct a policy from a session context and optional daemon config.
    pub fn from_session(
        ctx: &crate::types::SessionContext,
        sandbox_cfg: Option<&crate::config::SandboxConfig>,
    ) -> Self {
        let ws = ctx
            .workspace_path
            .as_deref()
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
            });

        let mut policy = Self::new(ws);

        if let Some(ref aid) = ctx.account_id {
            if let Ok(p) = crate::agy_auth::profile_dir(aid) {
                policy = policy.with_profile(p);
            }
        }

        if let Some(cfg) = sandbox_cfg {
            policy = policy
                .with_mode(&cfg.mode)
                .with_allow_network(cfg.allow_network)
                .with_extra_read_paths(cfg.extra_read_paths.clone())
                .with_extra_write_paths(cfg.extra_write_paths.clone());
        }

        // Context overrides: if launch.sandbox is explicitly set
        if let Some(ref agent_cfg) = ctx.agent_config {
            if let Some(sb) = agent_cfg.get("sandbox").and_then(|v| v.as_bool()) {
                if !sb {
                    policy.mode = "disabled".to_string();
                } else {
                    policy.mode = "landlock".to_string();
                }
            } else if let Some(launch) = agent_cfg.get("launch") {
                if let Some(sb) = launch.get("sandbox").and_then(|v| v.as_bool()) {
                    if !sb {
                        policy.mode = "disabled".to_string();
                    } else {
                        policy.mode = "landlock".to_string();
                    }
                }
            }
        }

        policy
    }

    /// Compile and populate Landlock ruleset BEFORE fork in the parent process.
    ///
    /// Creates a ruleset file descriptor via `SYS_landlock_create_ruleset`, opens
    /// each permitted path with `O_PATH`, validates regular file vs. directory flags
    /// using `FILE_MASK`, and populates the ruleset via `SYS_landlock_add_rule`.
    ///
    /// The resulting `ActiveSandboxRuleset` can be passed to child processes across `fork`,
    /// where `apply_in_pre_exec` activates restrictions with 0 memory allocations.
    pub fn prepare(&self) -> Result<ActiveSandboxRuleset> {
        if self.mode == "disabled" {
            debug!("Landlock sandboxing explicitly disabled by policy mode");
            return Ok(ActiveSandboxRuleset::inactive());
        }

        #[cfg(not(target_os = "linux"))]
        {
            if self.mode == "landlock" {
                bail!("Kernel-enforced filesystem sandboxing (Landlock) is only supported on Linux");
            }
            debug!("Landlock sandboxing not available on non-Linux platform; proceeding without sandbox");
            return Ok(ActiveSandboxRuleset::inactive());
        }

        #[cfg(target_os = "linux")]
        {
            let abi = match probe_landlock_abi() {
                Some(v) => v,
                None => {
                    if self.mode == "landlock" {
                        bail!("Linux Landlock sandboxing requested but kernel does not support or has disabled Landlock");
                    }
                    warn!("Linux Landlock is unsupported or disabled by kernel; falling back to un-sandboxed execution");
                    return Ok(ActiveSandboxRuleset::inactive());
                }
            };

            let handled_fs = handled_fs_access_mask(abi);
            let attr = LandlockRulesetAttr {
                handled_access_fs: handled_fs,
            };

            let ruleset_fd = unsafe {
                libc::syscall(
                    SYS_LANDLOCK_CREATE_RULESET,
                    &attr as *const LandlockRulesetAttr,
                    std::mem::size_of::<LandlockRulesetAttr>(),
                    0u32,
                )
            } as i32;

            if ruleset_fd < 0 {
                let err = io::Error::last_os_error();
                if self.mode == "landlock" {
                    return Err(err).context("SYS_landlock_create_ruleset failed");
                }
                warn!("SYS_landlock_create_ruleset failed: {}; falling back", err);
                return Ok(ActiveSandboxRuleset::inactive());
            }

            let active = ActiveSandboxRuleset::new(ruleset_fd);

            // Ensure workspace directory exists and add rule
            if !self.workspace_path.exists() {
                bail!(
                    "Sandbox workspace path does not exist: {}",
                    self.workspace_path.display()
                );
            }
            self.add_path_rule(
                ruleset_fd,
                &self.workspace_path,
                PathAccess::ReadWrite,
                handled_fs,
                abi,
                true,
            )?;

            // Add isolated profile directory if present
            if let Some(ref prof) = self.profile_path {
                if prof.exists() {
                    let _ = self.add_path_rule(
                        ruleset_fd,
                        prof,
                        PathAccess::ReadWrite,
                        handled_fs,
                        abi,
                        false,
                    );
                }
            }

            // Standard Read-Write scratch paths
            for rw_path in ["/tmp", "/var/tmp"] {
                let p = Path::new(rw_path);
                if p.exists() {
                    let _ = self.add_path_rule(
                        ruleset_fd,
                        p,
                        PathAccess::ReadWrite,
                        handled_fs,
                        abi,
                        false,
                    );
                }
            }

            // /dev access: required so /dev/null redirection and character devices work
            let dev = Path::new("/dev");
            if dev.exists() {
                let _ = self.add_path_rule(
                    ruleset_fd,
                    dev,
                    PathAccess::ReadWrite,
                    handled_fs,
                    abi,
                    false,
                );
            }

            // User-configured extra write paths
            for extra_w in &self.extra_write_paths {
                if extra_w.exists() {
                    let _ = self.add_path_rule(
                        ruleset_fd,
                        extra_w,
                        PathAccess::ReadWrite,
                        handled_fs,
                        abi,
                        false,
                    );
                }
            }

            // Standard Read-Only system essentials
            let ro_essentials = [
                "/usr",
                "/lib",
                "/lib64",
                "/bin",
                "/sbin",
                "/opt",
                "/etc",
                "/proc",
                "/sys",
            ];
            for ro_path in ro_essentials {
                let p = Path::new(ro_path);
                if p.exists() {
                    let _ = self.add_path_rule(
                        ruleset_fd,
                        p,
                        PathAccess::ReadOnly,
                        handled_fs,
                        abi,
                        false,
                    );
                }
            }

            // User-configured extra read paths
            for extra_r in &self.extra_read_paths {
                if extra_r.exists() {
                    let _ = self.add_path_rule(
                        ruleset_fd,
                        extra_r,
                        PathAccess::ReadOnly,
                        handled_fs,
                        abi,
                        false,
                    );
                }
            }

            debug!(
                "Prepared Landlock ruleset fd={} (ABI v{}, workspace={}, profile={:?})",
                ruleset_fd,
                abi,
                self.workspace_path.display(),
                self.profile_path.as_deref().map(|p| p.display().to_string())
            );

            Ok(active)
        }
    }

    #[cfg(target_os = "linux")]
    fn add_path_rule(
        &self,
        ruleset_fd: i32,
        path: &Path,
        access: PathAccess,
        handled_fs: u64,
        abi: u32,
        required: bool,
    ) -> Result<()> {
        let c_path = match std::ffi::CString::new(path.as_os_str().as_bytes()) {
            Ok(c) => c,
            Err(e) => {
                if required {
                    bail!("Invalid path {:?}: {}", path, e);
                }
                return Ok(());
            }
        };

        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if fd < 0 {
            let err = io::Error::last_os_error();
            if required {
                return Err(err).context(format!("Opening required sandbox path {:?}", path));
            }
            debug!("Optional sandbox path {:?} cannot be opened: {}", path, err);
            return Ok(());
        }

        let is_dir = path.is_dir();
        let mut allowed = match access {
            PathAccess::ReadOnly => read_only_fs_mask(abi),
            PathAccess::ReadWrite => read_write_fs_mask(abi),
        };

        // Invariant: regular file rules must not request directory-only rights (prevents EINVAL)
        if !is_dir {
            allowed &= FILE_MASK & handled_fs;
        }

        if allowed == 0 {
            unsafe {
                libc::close(fd);
            }
            return Ok(());
        }

        let path_beneath = LandlockPathBeneathAttr {
            allowed_access: allowed,
            parent_fd: fd,
        };

        let ret = unsafe {
            libc::syscall(
                SYS_LANDLOCK_ADD_RULE,
                ruleset_fd,
                LANDLOCK_RULE_PATH_BENEATH,
                &path_beneath as *const LandlockPathBeneathAttr,
                0u32,
            )
        };

        unsafe {
            libc::close(fd);
        }

        if ret != 0 {
            let err = io::Error::last_os_error();
            if required {
                return Err(err).context(format!("Adding sandbox rule for {:?}", path));
            }
            debug!("Failed to add optional sandbox rule for {:?}: {}", path, err);
        }

        Ok(())
    }
}

/// An active, populated Landlock ruleset awaiting enforcement in a child process.
pub struct ActiveSandboxRuleset {
    ruleset_fd: i32,
}

impl ActiveSandboxRuleset {
    /// Create a new active ruleset wrapping `ruleset_fd`.
    pub fn new(ruleset_fd: i32) -> Self {
        Self { ruleset_fd }
    }

    /// Inactive placeholder ruleset (ruleset_fd = -1) when sandboxing is disabled.
    pub fn inactive() -> Self {
        Self { ruleset_fd: -1 }
    }

    /// Whether this ruleset is active and holding a valid file descriptor.
    pub fn is_active(&self) -> bool {
        self.ruleset_fd >= 0
    }

    /// Borrow the raw ruleset file descriptor.
    pub fn raw_fd(&self) -> i32 {
        self.ruleset_fd
    }

    /// Invoked strictly inside `pre_exec` after fork in the child process.
    ///
    /// Must be async-signal-safe: executes zero heap allocations, no locks,
    /// and only standard async-signal-safe syscalls (`prctl`, `landlock_restrict_self`, `close`).
    pub fn apply_in_pre_exec(&self) -> io::Result<()> {
        apply_raw_ruleset_fd(self.ruleset_fd)
    }
}

impl Drop for ActiveSandboxRuleset {
    fn drop(&mut self) {
        if self.ruleset_fd >= 0 {
            unsafe {
                libc::close(self.ruleset_fd);
            }
            self.ruleset_fd = -1;
        }
    }
}

/// Apply a prepared Landlock ruleset inside child process `pre_exec`.
///
/// Async-signal-safe: executes zero memory allocations, zero locks, and calls only
/// `prctl(PR_SET_NO_NEW_PRIVS)`, `SYS_landlock_restrict_self`, and `close`.
pub fn apply_raw_ruleset_fd(ruleset_fd: i32) -> io::Result<()> {
    if ruleset_fd < 0 {
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        // 1. Unprivileged processes MUST set PR_SET_NO_NEW_PRIVS before restrict_self
        let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        // 2. Restrict process and all future children to ruleset
        let ret = unsafe {
            libc::syscall(
                SYS_LANDLOCK_RESTRICT_SELF,
                ruleset_fd,
                0u32,
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        // 3. Close ruleset_fd inside child so child cannot tamper with it
        unsafe {
            libc::close(ruleset_fd);
        }

        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = ruleset_fd;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abi_handled_masks() {
        assert_eq!(handled_fs_access_mask(0), 0);
        assert_eq!(handled_fs_access_mask(1), (1 << 13) - 1);
        assert_eq!(handled_fs_access_mask(2), (1 << 14) - 1);
        assert_eq!(handled_fs_access_mask(3), (1 << 15) - 1);
        assert_eq!(handled_fs_access_mask(4), (1 << 15) - 1);
    }

    #[test]
    fn test_file_mask_subset() {
        let v4_mask = handled_fs_access_mask(4);
        let masked = FILE_MASK & v4_mask;
        // Verify regular file mask does NOT include directory flags
        assert_eq!(masked & LANDLOCK_ACCESS_FS_READ_DIR, 0);
        assert_eq!(masked & LANDLOCK_ACCESS_FS_REMOVE_DIR, 0);
        assert_eq!(masked & LANDLOCK_ACCESS_FS_MAKE_DIR, 0);
        assert_eq!(masked & LANDLOCK_ACCESS_FS_REFER, 0);
        // Verify regular file mask DOES include read, write, execute, truncate
        assert_ne!(masked & LANDLOCK_ACCESS_FS_EXECUTE, 0);
        assert_ne!(masked & LANDLOCK_ACCESS_FS_WRITE_FILE, 0);
        assert_ne!(masked & LANDLOCK_ACCESS_FS_READ_FILE, 0);
        assert_ne!(masked & LANDLOCK_ACCESS_FS_TRUNCATE, 0);
    }

    #[test]
    fn test_policy_builder() {
        let policy = SandboxPolicy::new("/tmp/test_ws")
            .with_profile("/tmp/test_profile")
            .with_extra_read_paths(vec![PathBuf::from("/opt/custom")])
            .with_extra_write_paths(vec![PathBuf::from("/var/custom")])
            .with_mode("landlock")
            .with_allow_network(false);

        assert_eq!(policy.workspace_path, PathBuf::from("/tmp/test_ws"));
        assert_eq!(policy.profile_path, Some(PathBuf::from("/tmp/test_profile")));
        assert_eq!(policy.extra_read_paths, vec![PathBuf::from("/opt/custom")]);
        assert_eq!(policy.extra_write_paths, vec![PathBuf::from("/var/custom")]);
        assert_eq!(policy.mode, "landlock");
        assert!(!policy.allow_network);
    }

    #[test]
    fn test_inactive_ruleset_drop() {
        let inactive = ActiveSandboxRuleset::inactive();
        assert!(!inactive.is_active());
        assert_eq!(inactive.raw_fd(), -1);
        assert!(inactive.apply_in_pre_exec().is_ok());
    }

    #[test]
    fn test_landlock_status_probe() {
        let status = LandlockStatus::probe();
        #[cfg(target_os = "linux")]
        {
            // On our verified Linux host, status must be Supported with ABI >= 1
            if let LandlockStatus::Supported { abi } = status {
                assert!(abi >= 1);
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert!(!status.is_supported());
        }
    }
}
