//! Pure unit, plist, and XML definition generators for OS background services.

use std::path::Path;

/// Escapes XML special characters for safe inclusion in plists and XML task definitions.
pub fn xml_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

/// Generates a `systemd --user` service unit definition.
///
/// Conforms to systemd.service(5). Placed at `~/.config/systemd/user/cryptick-daemon.service`.
///
/// # Arguments
/// * `exec_path` - Path to the daemon binary.
/// * `args` - Optional command-line arguments (e.g. `&["run"]`). If empty, defaults to `&["run"]`.
pub fn generate_systemd_unit(exec_path: &Path, args: &[&str]) -> String {
    let exec_str = exec_path.display().to_string();
    assert!(
        !exec_str.contains(['\n', '\r']),
        "executable path must not contain newline characters"
    );
    for arg in args {
        assert!(
            !arg.contains(['\n', '\r']),
            "arguments must not contain newline characters"
        );
    }

    let args_str = if args.is_empty() {
        "run".to_string()
    } else {
        args.join(" ")
    };

    format!(
        "[Unit]
Description=Cryptick Token Host Daemon
Documentation=https://github.com/alphaseneca/cryptick-token-daemon
After=default.target

[Service]
Type=simple
ExecStart=\"{}\" {}
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
",
        exec_str, args_str
    )
}

/// Generates a macOS `launchd` LaunchAgent property list XML.
///
/// Per PROJECT.md §18, this MUST be a LaunchAgent (loaded into the Aqua GUI user session),
/// NEVER a LaunchDaemon (which runs as root before GUI login and cannot access CoreBluetooth TCC).
///
/// # Arguments
/// * `exec_path` - Path to the daemon binary.
/// * `label` - The reverse-DNS label (e.g. `"com.cryptick.daemon"`).
/// * `log_dir` - Directory for log output (e.g. `~/Library/Logs`).
/// * `extra_args` - Additional arguments beyond `exec_path` (defaults to `&["run"]` if empty).
pub fn generate_launchd_plist(
    exec_path: &Path,
    label: &str,
    log_dir: &Path,
    extra_args: &[&str],
) -> String {
    let mut args_xml = String::new();
    args_xml.push_str(&format!(
        "        <string>{}</string>\n",
        xml_escape(&exec_path.display().to_string())
    ));
    if extra_args.is_empty() {
        args_xml.push_str("        <string>run</string>\n");
    } else {
        for arg in extra_args {
            args_xml.push_str(&format!("        <string>{}</string>\n", xml_escape(arg)));
        }
    }

    let out_log = log_dir.join("cryptick-daemon.log");
    let err_log = log_dir.join("cryptick-daemon.err.log");

    format!(
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
    <key>Label</key>
    <string>{}</string>
    <key>ProgramArguments</key>
    <array>
{}    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{}</string>
    <key>StandardErrorPath</key>
    <string>{}</string>
</dict>
</plist>
",
        xml_escape(label),
        args_xml,
        xml_escape(&out_log.display().to_string()),
        xml_escape(&err_log.display().to_string())
    )
}

/// Generates a Windows Task Scheduler XML task definition conforming to Schema v1.2.
///
/// Registers a user-level background task with a LogonTrigger running under LeastPrivilege
/// in the user's interactive session to ensure WinRT Bluetooth and named pipe access.
///
/// # Arguments
/// * `exec_path` - Path to `cryptick-daemon.exe`.
/// * `task_name` - Task name / URI (e.g. `"CryptickDaemon"`).
/// * `args` - Command-line arguments for Exec action (defaults to `&["run"]` if empty).
pub fn generate_windows_task_xml(exec_path: &Path, task_name: &str, args: &[&str]) -> String {
    let args_str = if args.is_empty() {
        "run".to_string()
    } else {
        args.join(" ")
    };

    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">
  <RegistrationInfo>
    <Description>Cryptick Token Host Daemon</Description>
    <URI>\\{}</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id=\"Author\">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context=\"Author\">
    <Exec>
      <Command>{}</Command>
      <Arguments>{}</Arguments>
    </Exec>
  </Actions>
</Task>
",
        xml_escape(task_name),
        xml_escape(&exec_path.display().to_string()),
        xml_escape(&args_str)
    )
}
