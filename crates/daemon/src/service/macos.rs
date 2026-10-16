//! macOS launchd LaunchAgent service management.

use super::{generator::generate_launchd_plist, is_ipc_connectable, ServiceManager, ServiceStatus};
use std::{
    io,
    path::{Path, PathBuf},
    process::Command,
};

/// Service manager for macOS using `launchd` user LaunchAgents.
#[derive(Debug, Default, Clone)]
pub struct LaunchdServiceManager;

impl LaunchdServiceManager {
    /// Service label for the macOS LaunchAgent.
    pub const LABEL: &'static str = "com.cryptick.daemon";

    /// Creates a new `LaunchdServiceManager`.
    pub fn new() -> Self {
        Self
    }
}

impl ServiceManager for LaunchdServiceManager {
    fn platform_name(&self) -> &'static str {
        "macOS (launchd)"
    }

    fn unit_path(&self) -> io::Result<PathBuf> {
        let home = std::env::var_os("HOME").ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "HOME environment variable not set")
        })?;
        Ok(PathBuf::from(home)
            .join("Library")
            .join("LaunchAgents")
            .join(format!("{}.plist", Self::LABEL)))
    }

    fn install(&self, exec_path: &Path, extra_args: &[&str]) -> io::Result<()> {
        let home = std::env::var_os("HOME").ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "HOME environment variable not set")
        })?;
        let home_path = PathBuf::from(home);
        let log_dir = home_path.join("Library").join("Logs");
        std::fs::create_dir_all(&log_dir)?;

        let unit_path = self.unit_path()?;
        if let Some(parent) = unit_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let plist_content = generate_launchd_plist(exec_path, Self::LABEL, &log_dir, extra_args);
        std::fs::write(&unit_path, plist_content)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&unit_path, std::fs::Permissions::from_mode(0o644));
        }

        // Unload first if already loaded to avoid error on reload
        let _ = Command::new("launchctl")
            .args(["unload", "-w"])
            .arg(&unit_path)
            .output();

        let output = Command::new("launchctl")
            .args(["load", "-w"])
            .arg(&unit_path)
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::other(format!(
                "failed to load launchd LaunchAgent: {stderr}"
            )));
        }

        Ok(())
    }

    fn uninstall(&self) -> io::Result<()> {
        let unit_path = self.unit_path()?;

        if unit_path.exists() {
            let _ = Command::new("launchctl")
                .args(["unload", "-w"])
                .arg(&unit_path)
                .output();

            std::fs::remove_file(&unit_path)?;
        }

        Ok(())
    }

    fn status(&self) -> io::Result<ServiceStatus> {
        let unit_path = self
            .unit_path()
            .unwrap_or_else(|_| PathBuf::from("~/Library/LaunchAgents/com.cryptick.daemon.plist"));
        let unit_exists = unit_path.is_file();

        let output = Command::new("launchctl")
            .args(["list", Self::LABEL])
            .output();

        let (service_running, service_details) = match output {
            Ok(out) => {
                let success = out.status.success();
                let text = String::from_utf8_lossy(&out.stdout);
                let pid = text.lines().find_map(|line| {
                    let trimmed = line.trim();
                    if trimmed.starts_with("\"PID\"") {
                        trimmed
                            .split('=')
                            .nth(1)
                            .map(|v| v.trim().trim_matches(';').trim().to_string())
                    } else {
                        None
                    }
                });

                if let Some(pid_str) = pid {
                    (true, Some(format!("running (PID {pid_str})")))
                } else if success {
                    (true, Some("loaded".to_string()))
                } else {
                    (false, None)
                }
            }
            Err(_) => (false, None),
        };

        let endpoint = ipc::IpcEndpoint::default_platform();
        let endpoint_connectable = endpoint.as_ref().is_some_and(is_ipc_connectable);
        let endpoint_str = endpoint
            .map(|ep| ep.display_target())
            .unwrap_or_else(|| "none".to_string());

        Ok(ServiceStatus {
            platform: self.platform_name().to_string(),
            unit_path,
            unit_exists,
            service_running,
            service_details,
            endpoint: endpoint_str,
            endpoint_connectable,
        })
    }
}
