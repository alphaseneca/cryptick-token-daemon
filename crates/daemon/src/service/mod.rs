//! Service controller interface and status tracking for background services.

pub mod generator;
pub mod linux;
pub mod macos;
pub mod windows;

use std::{
    io,
    path::{Path, PathBuf},
};

/// Status of the background service and IPC endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceStatus {
    /// Target platform description (e.g. "macOS (launchd)").
    pub platform: String,
    /// Path to the unit / plist / XML definition file.
    pub unit_path: PathBuf,
    /// Whether the unit file exists on disk.
    pub unit_exists: bool,
    /// Whether the background service is currently loaded/active.
    pub service_running: bool,
    /// Diagnostic details from the supervisor (e.g. PID or status message).
    pub service_details: Option<String>,
    /// The IPC endpoint checked.
    pub endpoint: String,
    /// Whether the IPC endpoint is connectable.
    pub endpoint_connectable: bool,
}

impl ServiceStatus {
    /// Returns `true` if the service definition exists, is running, and the IPC endpoint is connectable.
    pub fn is_healthy(&self) -> bool {
        self.unit_exists && self.service_running && self.endpoint_connectable
    }

    /// Formats a human-readable multi-line summary of the service status.
    pub fn display_summary(&self) -> String {
        let overall = if self.is_healthy() {
            "ACTIVE"
        } else if !self.unit_exists && !self.service_running {
            "NOT_INSTALLED"
        } else if self.unit_exists && !self.service_running {
            "STOPPED"
        } else {
            "DEGRADED"
        };

        format!(
            "Platform: {}\n\
             Service Unit: {}\n\
               Installed: {}\n\
               Running: {}\n\
             IPC Endpoint: {}\n\
               Connectable: {}\n\
             Overall: {}\n",
            self.platform,
            self.unit_path.display(),
            if self.unit_exists { "yes" } else { "no (file not found)" },
            if self.service_running {
                self.service_details.as_deref().unwrap_or("yes")
            } else {
                "no"
            },
            self.endpoint,
            if self.endpoint_connectable { "yes" } else { "no" },
            overall
        )
    }
}

/// Interface for operating system service management.
pub trait ServiceManager {
    /// The human-readable name of the platform supervisor (e.g. "Linux (systemd)").
    fn platform_name(&self) -> &'static str;

    /// Resolves the unit / plist / task definition path.
    fn unit_path(&self) -> io::Result<PathBuf>;

    /// Installs and enables the background service.
    fn install(&self, exec_path: &Path, extra_args: &[&str]) -> io::Result<()>;

    /// Stops and removes the background service.
    fn uninstall(&self) -> io::Result<()>;

    /// Queries the service status.
    fn status(&self) -> io::Result<ServiceStatus>;
}

/// Checks whether an IPC endpoint is connectable.
pub fn is_ipc_connectable(endpoint: &ipc::IpcEndpoint) -> bool {
    match endpoint {
        ipc::IpcEndpoint::UnixSocket(path) => {
            #[cfg(unix)]
            {
                std::os::unix::net::UnixStream::connect(path).is_ok()
            }
            #[cfg(not(unix))]
            {
                let _ = path;
                false
            }
        }
        ipc::IpcEndpoint::NamedPipe(pipe_path) => {
            #[cfg(windows)]
            {
                std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(pipe_path)
                    .is_ok()
            }
            #[cfg(not(windows))]
            {
                let _ = pipe_path;
                false
            }
        }
    }
}

/// Resolves the active service manager for the current operating system.
pub fn current_service_manager() -> Box<dyn ServiceManager> {
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::LaunchdServiceManager::new())
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::SystemdServiceManager::new())
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(windows::WindowsTaskServiceManager::new())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        Box::new(UnsupportedServiceManager)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
struct UnsupportedServiceManager;

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
impl ServiceManager for UnsupportedServiceManager {
    fn platform_name(&self) -> &'static str {
        "Unsupported"
    }

    fn unit_path(&self) -> io::Result<PathBuf> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "service management is unsupported on this platform",
        ))
    }

    fn install(&self, _exec_path: &Path, _extra_args: &[&str]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "service management is unsupported on this platform",
        ))
    }

    fn uninstall(&self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "service management is unsupported on this platform",
        ))
    }

    fn status(&self) -> io::Result<ServiceStatus> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "service management is unsupported on this platform",
        ))
    }
}
