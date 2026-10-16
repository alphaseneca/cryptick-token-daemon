//! Windows Task Scheduler service management.

use super::{
    generator::generate_windows_task_xml, is_ipc_connectable, ServiceManager, ServiceStatus,
};
use std::{
    io,
    path::{Path, PathBuf},
    process::Command,
};

/// Service manager for Windows using Task Scheduler.
#[derive(Debug, Default, Clone)]
pub struct WindowsTaskServiceManager;

impl WindowsTaskServiceManager {
    /// Task name registered with Windows Task Scheduler.
    pub const TASK_NAME: &'static str = "CryptickDaemon";

    /// Creates a new `WindowsTaskServiceManager`.
    pub fn new() -> Self {
        Self
    }
}

impl ServiceManager for WindowsTaskServiceManager {
    fn platform_name(&self) -> &'static str {
        "Windows (Task Scheduler)"
    }

    fn unit_path(&self) -> io::Result<PathBuf> {
        let base = std::env::var_os("LOCALAPPDATA")
            .or_else(|| std::env::var_os("APPDATA"))
            .or_else(|| std::env::var_os("USERPROFILE"))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "neither LOCALAPPDATA, APPDATA, nor USERPROFILE is set",
                )
            })?;

        Ok(PathBuf::from(base)
            .join("cryptick")
            .join("cryptick-daemon-task.xml"))
    }

    fn install(&self, exec_path: &Path, extra_args: &[&str]) -> io::Result<()> {
        let unit_path = self.unit_path()?;
        if let Some(parent) = unit_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let xml_content = generate_windows_task_xml(exec_path, Self::TASK_NAME, extra_args);
        std::fs::write(&unit_path, xml_content)?;

        let output = Command::new("schtasks")
            .args([
                "/create",
                "/tn",
                Self::TASK_NAME,
                "/xml",
                &unit_path.display().to_string(),
                "/f",
            ])
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(io::Error::other(format!(
                "failed to register Windows task: {stderr}"
            )));
        }

        let _ = Command::new("schtasks")
            .args(["/run", "/tn", Self::TASK_NAME])
            .output();

        Ok(())
    }

    fn uninstall(&self) -> io::Result<()> {
        let _ = Command::new("schtasks")
            .args(["/end", "/tn", Self::TASK_NAME])
            .output();

        let _ = Command::new("schtasks")
            .args(["/delete", "/tn", Self::TASK_NAME, "/f"])
            .output();

        let unit_path = self.unit_path()?;
        if unit_path.exists() {
            std::fs::remove_file(&unit_path)?;
        }

        Ok(())
    }

    fn status(&self) -> io::Result<ServiceStatus> {
        let unit_path = self
            .unit_path()
            .unwrap_or_else(|_| PathBuf::from(r"%LOCALAPPDATA%\cryptick\cryptick-daemon-task.xml"));
        let unit_exists = unit_path.is_file();

        let output = Command::new("schtasks")
            .args(["/query", "/tn", Self::TASK_NAME, "/fo", "LIST"])
            .output();

        let (service_running, service_details) = match output {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let running = stdout.contains("Running");
                let status_line = stdout
                    .lines()
                    .find(|line| line.starts_with("Status:"))
                    .map(|l| l.trim().to_string());
                (running, status_line)
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
