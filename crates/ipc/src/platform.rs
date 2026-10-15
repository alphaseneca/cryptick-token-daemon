//! OS-independent IPC endpoint definitions and discovery.
//!
//! Provides platform-native default endpoints:
//! - **Linux**: `$XDG_RUNTIME_DIR/cryptick/daemon.sock` or `~/.cryptick/daemon.sock`
//! - **macOS**: `~/Library/Application Support/cryptick/daemon.sock`
//! - **Windows**: `\\.\pipe\cryptick-daemon`

use std::path::PathBuf;

/// Default named pipe identifier on Windows.
pub const WINDOWS_NAMED_PIPE: &str = r"\\.\pipe\cryptick-daemon";

/// An operating system IPC endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcEndpoint {
    /// A Unix domain socket at a filesystem path (Linux, macOS).
    UnixSocket(PathBuf),
    /// A Windows Named Pipe.
    NamedPipe(String),
}

impl IpcEndpoint {
    /// Returns the standard Windows named pipe endpoint (`\\.\pipe\cryptick-daemon`).
    pub fn windows_named_pipe() -> Self {
        Self::NamedPipe(WINDOWS_NAMED_PIPE.to_string())
    }

    /// Returns `true` if this endpoint represents a Unix domain socket.
    pub fn is_unix_socket(&self) -> bool {
        matches!(self, Self::UnixSocket(_))
    }

    /// Returns `true` if this endpoint represents a Windows named pipe.
    pub fn is_named_pipe(&self) -> bool {
        matches!(self, Self::NamedPipe(_))
    }

    /// Returns the default platform-native IPC endpoint.
    pub fn default_platform() -> Option<Self> {
        #[cfg(windows)]
        {
            Some(Self::windows_named_pipe())
        }
        #[cfg(unix)]
        {
            crate::default_socket_path().map(IpcEndpoint::UnixSocket)
        }
        #[cfg(not(any(windows, unix)))]
        {
            None
        }
    }

    /// Formats the endpoint for display or logging.
    pub fn display_target(&self) -> String {
        match self {
            IpcEndpoint::UnixSocket(path) => path.display().to_string(),
            IpcEndpoint::NamedPipe(pipe) => pipe.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_named_pipe_endpoint_format() {
        let endpoint = IpcEndpoint::windows_named_pipe();
        assert!(endpoint.is_named_pipe());
        assert!(!endpoint.is_unix_socket());
        assert_eq!(endpoint.display_target(), r"\\.\pipe\cryptick-daemon");
    }

    #[test]
    fn unix_socket_endpoint_format() {
        let endpoint = IpcEndpoint::UnixSocket(PathBuf::from("/tmp/test.sock"));
        assert!(endpoint.is_unix_socket());
        assert!(!endpoint.is_named_pipe());
        assert_eq!(endpoint.display_target(), "/tmp/test.sock");
    }

    #[test]
    fn default_platform_endpoint_resolves_on_current_os() {
        let ep = IpcEndpoint::default_platform();
        assert!(ep.is_some());
    }
}
