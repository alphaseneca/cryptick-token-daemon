//! Linux systemd user service management.

use super::{generator::generate_systemd_unit, is_ipc_connectable, ServiceManager, ServiceStatus};
use std::{
    io,
    path::{Path, PathBuf},
    process::Command,
};

/// Service manager for Linux using `systemd --user`.
#[derive(Debug, Default, Clone)]
pub struct SystemdServiceManager;

impl SystemdServiceManager {
    /// Creates a new `SystemdServiceManager`.
    pub fn new() -> Self {
        Self
    }
}

impl ServiceManager for SystemdServiceManager {
    fn platform_name(&self) -> &'static str {
        "Linux (systemd)"
    }

    fn unit_path(&self) -> io::Result<PathBuf> {
        if let Some(config_home) = std::env::var_os("XDG_CONFIG_HOME") {
            return Ok(PathBuf::from(config_home)
                .join("systemd")
                .join("user")
                .join("cryptick-daemon.service"));
        }
        let home = std::env::var_os("HOME").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "neither XDG_CONFIG_HOME nor HOME is set",
            )
        })?;
        Ok(PathBuf::from(home)
            .join(".config")
            .join("systemd")
            .join("user")
            .join("cryptick-daemon.service"))
    }

    fn install(&self, exec_path: &Path, extra_args: &[&str]) -> io::Result<()> {
        let unit_path = self.unit_path()?;
        if let Some(parent) = unit_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let unit_content = generate_systemd_unit(exec_path, extra_args);
        std::fs::write(&unit_path, unit_content)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&unit_path, std::fs::Permissions::from_mode(0o644));
        }

        let _ = Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .output();

        let output = Command::new("systemctl")
            .args(["--user", "enable", "--now", "cryptick-daemon.service"])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::other(format!(
                "failed to enable and start systemd service: {stderr}"
            )));
        }

        Ok(())
    }

    fn uninstall(&self) -> io::Result<()> {
        let _ = Command::new("systemctl")
            .args(["--user", "stop", "cryptick-daemon.service"])
            .output();

        let _ = Command::new("systemctl")
            .args(["--user", "disable", "cryptick-daemon.service"])
            .output();

        let unit_path = self.unit_path()?;
        if unit_path.exists() {
            std::fs::remove_file(&unit_path)?;
        }

        let _ = Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .output();

        Ok(())
    }

    fn status(&self) -> io::Result<ServiceStatus> {
        let unit_path = self
            .unit_path()
            .unwrap_or_else(|_| PathBuf::from("~/.config/systemd/user/cryptick-daemon.service"));
        let unit_exists = unit_path.is_file();

        let output = Command::new("systemctl")
            .args(["--user", "is-active", "cryptick-daemon.service"])
            .output();

        let (service_running, service_details) = match output {
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
                let running = text == "active";
                (running, if text.is_empty() { None } else { Some(text) })
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
