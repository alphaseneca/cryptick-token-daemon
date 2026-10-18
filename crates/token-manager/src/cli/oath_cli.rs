//! CLI subcommand handlers for `tickctl oath`.

use crate::access::{forget_all_keys, forget_key, remember_key};
use crate::error::ManagerError;
use crate::oath::{
    calculate_code, delete_account, list_accounts, put_account, rename_account, reset_oath,
    select_oath, set_access_password, AddAccountOptions,
};
use crate::otpauth::{decode_base32, HashAlgorithm, OathType, OtpAuthUri};
use crate::transport::TokenTransport;
use std::fs;
use std::io::{self, Write};

/// Whether an account counts as "hidden" for `--show-hidden` purposes.
///
/// Matches ykman's own definition exactly (`is_hidden` in
/// `yubikey-manager/ykman/oath.py`): a credential is hidden when its issuer
/// is literally the string `_hidden` — nothing to do with a prefix or a
/// separate flag on the device, just that one reserved issuer name ykman's
/// own tooling uses to stash credentials it doesn't want `accounts
/// list`/`code` to show by default. Account names in this crate are
/// already the canonical `Issuer:Account` string (see
/// `OtpAuthUri::canonical_name`), so the issuer is recovered by splitting
/// on the first colon.
fn is_hidden_account(name: &str) -> bool {
    name.split_once(':')
        .map(|(issuer, _)| issuer == "_hidden")
        .unwrap_or(false)
}

/// Handles all `tickctl oath ...` subcommands.
pub fn handle_oath_command(
    transport: &mut dyn TokenTransport,
    args: &[String],
) -> Result<(), ManagerError> {
    if args.is_empty() {
        print_oath_help();
        return Ok(());
    }

    match args[0].as_str() {
        "-h" | "--help" | "help" => {
            print_oath_help();
            Ok(())
        }
        "info" => run_oath_info(transport, &args[1..]),
        "reset" => run_oath_reset(transport, &args[1..]),
        "access" => run_oath_access(transport, &args[1..]),
        "accounts" => run_oath_accounts(transport, &args[1..]),
        unknown => Err(ManagerError::InvalidInput(format!(
            "Unknown oath subcommand '{unknown}'. Run 'tickctl oath --help' for available commands."
        ))),
    }
}

/// Prints `tickctl oath --help` usage text.
pub fn print_oath_help() {
    println!(
        "Usage: tickctl oath [COMMAND] [OPTIONS]\n\n\
         Manage OATH (TOTP / HOTP) authentication on Cryptick Token.\n\n\
         Commands:\n\
           info                  Display OATH application status and configuration\n\
           reset                 Reset OATH application, erasing all accounts and passwords\n\
           access                Manage OATH application access password\n\
           accounts              Manage and calculate OATH accounts\n\n\
         Options:\n\
           -h, --help            Show this help message\n"
    );
}

// ---------------------------------------------------------------------------
// 1. OATH INFO
// ---------------------------------------------------------------------------

fn run_oath_info(transport: &mut dyn TokenTransport, _args: &[String]) -> Result<(), ManagerError> {
    let applet = select_oath(transport)?;
    let accounts_res = list_accounts(transport, None);

    println!("=== OATH Application Status ===");
    println!(
        "OATH version     : {}.{}.{}",
        applet.version.0, applet.version.1, applet.version.2
    );
    println!(
        "Password protected: {}",
        if applet.password_protected {
            "Yes"
        } else {
            "No"
        }
    );
    if let Ok(accs) = accounts_res {
        println!("Enrolled accounts: {}", accs.len());
        let totp_count = accs
            .iter()
            .filter(|a| a.oath_type == OathType::Totp)
            .count();
        let hotp_count = accs
            .iter()
            .filter(|a| a.oath_type == OathType::Hotp)
            .count();
        let touch_count = accs.iter().filter(|a| a.touch_required).count();
        println!("  TOTP accounts  : {}", totp_count);
        println!("  HOTP accounts  : {}", hotp_count);
        println!("  Touch protected: {}", touch_count);
    } else {
        println!("Enrolled accounts: Locked (Password authentication required)");
    }
    println!("Hardware storage : Encrypted LittleFS (Zero-Trust Passer Model)");
    Ok(())
}

// ---------------------------------------------------------------------------
// 2. OATH RESET
// ---------------------------------------------------------------------------

fn run_oath_reset(transport: &mut dyn TokenTransport, args: &[String]) -> Result<(), ManagerError> {
    let mut force = false;
    for arg in args {
        if arg == "-f" || arg == "--force" {
            force = true;
        }
    }

    if !force {
        print!("WARNING: This will delete all stored OATH accounts and reset the password! Proceed? [y/N]: ");
        io::stdout().flush().map_err(|e| e.to_string())?;
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .map_err(|e| e.to_string())?;
        let trimmed = input.trim().to_ascii_lowercase();
        if trimmed != "y" && trimmed != "yes" {
            println!("Reset cancelled.");
            return Ok(());
        }
    }

    reset_oath(transport)?;
    println!("Successfully reset OATH application. All accounts and passwords cleared.");
    Ok(())
}

// ---------------------------------------------------------------------------
// 3. OATH ACCESS
// ---------------------------------------------------------------------------

fn run_oath_access(transport: &mut dyn TokenTransport, args: &[String]) -> Result<(), ManagerError> {
    if args.is_empty() {
        println!(
            "Usage: tickctl oath access [COMMAND] [OPTIONS]\n\n\
             Manage OATH application access password.\n\n\
             Commands:\n\
               change    Change or set the access password\n\
               forget    Forget remembered passwords from this machine\n\
               remember  Remember a password on this machine\n"
        );
        return Ok(());
    }

    match args[0].as_str() {
        "change" => run_access_change(transport, &args[1..]),
        "forget" => run_access_forget(transport, &args[1..]),
        "remember" => run_access_remember(transport, &args[1..]),
        other => Err(ManagerError::InvalidInput(format!(
            "Unknown access subcommand '{other}'"
        ))),
    }
}

fn run_access_change(transport: &mut dyn TokenTransport, args: &[String]) -> Result<(), ManagerError> {
    let mut clear = false;
    let mut password = None;
    let mut new_password = None;
    let mut remember = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--clear" => clear = true,
            "-p" | "--password" => {
                i += 1;
                if i < args.len() {
                    password = Some(args[i].clone());
                }
            }
            "-n" | "--new-password" => {
                i += 1;
                if i < args.len() {
                    new_password = Some(args[i].clone());
                }
            }
            "-r" | "--remember" => remember = true,
            other => return Err(ManagerError::InvalidInput(format!("Unknown option '{other}'"))),
        }
        i += 1;
    }

    let _applet = select_oath(transport)?;

    if clear {
        // Clearing current password
        let pwd_ref = password.as_deref();
        set_access_password(transport, pwd_ref, None, false)?;
        println!("OATH password cleared successfully.");
        return Ok(());
    }

    // Setting or changing password
    let new_pwd = match new_password {
        Some(p) => p,
        None => {
            print!("Enter new OATH password: ");
            io::stdout().flush().map_err(|e| e.to_string())?;
            let mut buf = String::new();
            io::stdin().read_line(&mut buf).map_err(|e| e.to_string())?;
            buf.trim().to_string()
        }
    };

    if new_pwd.is_empty() {
        return Err(ManagerError::InvalidInput(
            "Password cannot be empty (use '--clear' to remove password)".into(),
        ));
    }

    let curr_pwd = password.as_deref();
    set_access_password(transport, curr_pwd, Some(&new_pwd), remember)?;

    if remember {
        println!("OATH password changed and remembered on this computer.");
    } else {
        println!("OATH password changed successfully.");
    }

    Ok(())
}

fn run_access_forget(transport: &mut dyn TokenTransport, args: &[String]) -> Result<(), ManagerError> {
    let mut all = false;
    for arg in args {
        if arg == "-a" || arg == "--all" {
            all = true;
        }
    }

    if all {
        let count = forget_all_keys()?;
        println!("Cleared {count} remembered OATH access keys.");
        return Ok(());
    }

    let applet = select_oath(transport)?;
    let removed = forget_key(&applet.device_id)?;
    if removed {
        println!("Remembered OATH access key removed for this token.");
    } else {
        println!("No remembered key found for this token.");
    }
    Ok(())
}

fn run_access_remember(transport: &mut dyn TokenTransport, args: &[String]) -> Result<(), ManagerError> {
    let mut password = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "-p" || args[i] == "--password" {
            i += 1;
            if i < args.len() {
                password = Some(args[i].clone());
            }
        }
        i += 1;
    }

    let pwd = match password {
        Some(p) => p,
        None => {
            print!("Enter OATH password to remember: ");
            io::stdout().flush().map_err(|e| e.to_string())?;
            let mut buf = String::new();
            io::stdin().read_line(&mut buf).map_err(|e| e.to_string())?;
            buf.trim().to_string()
        }
    };

    let applet = select_oath(transport)?;
    let key = crate::access::derive_access_key(&pwd, &applet.device_id);
    remember_key(&applet.device_id, &key)?;
    println!("Password successfully remembered for this token.");
    Ok(())
}

// ---------------------------------------------------------------------------
// 4. OATH ACCOUNTS
// ---------------------------------------------------------------------------

fn run_oath_accounts(transport: &mut dyn TokenTransport, args: &[String]) -> Result<(), ManagerError> {
    if args.is_empty() {
        println!(
            "Usage: tickctl oath accounts [COMMAND] [OPTIONS]\n\n\
             Manage and generate OATH accounts on Cryptick Token.\n\n\
             Commands:\n\
               list       List all configured accounts\n\
               code       Generate one-time code(s)\n\
               add        Add a new account\n\
               delete     Delete an existing account\n\
               rename     Rename an account\n\
               uri        Add an account from an otpauth:// URI\n\
               import     Import accounts from a file of URIs\n"
        );
        return Ok(());
    }

    match args[0].as_str() {
        "list" => run_accounts_list(transport, &args[1..]),
        "code" => run_accounts_code(transport, &args[1..]),
        "add" => run_accounts_add(transport, &args[1..]),
        "delete" => run_accounts_delete(transport, &args[1..]),
        "rename" => run_accounts_rename(transport, &args[1..]),
        "uri" => run_accounts_uri(transport, &args[1..]),
        "import" => run_accounts_import(transport, &args[1..]),
        other => Err(ManagerError::InvalidInput(format!(
            "Unknown accounts subcommand '{other}'"
        ))),
    }
}

fn run_accounts_list(transport: &mut dyn TokenTransport, args: &[String]) -> Result<(), ManagerError> {
    let mut single = false;
    let mut type_filter = None;
    let mut password = None;
    let mut show_hidden = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-s" | "--single" => single = true,
            // ykman: `-o, --oath-type`. `-H` is reserved for `--show-hidden`
            // below — tickctl previously had these swapped/wrong
            // (`-H` meant `--oath-type` and there was no real hidden-account
            // filter at all).
            "-o" | "--oath-type" => {
                i += 1;
                if i < args.len() {
                    type_filter = match args[i].to_ascii_uppercase().as_str() {
                        "TOTP" => Some(OathType::Totp),
                        "HOTP" => Some(OathType::Hotp),
                        other => {
                            return Err(ManagerError::InvalidInput(format!(
                                "Invalid oath-type '{other}'"
                            )))
                        }
                    };
                }
            }
            "-H" | "--show-hidden" => show_hidden = true,
            "-p" | "--password" => {
                i += 1;
                if i < args.len() {
                    password = Some(args[i].clone());
                }
            }
            _ => {}
        }
        i += 1;
    }

    let mut accounts = list_accounts(transport, password.as_deref())?;

    if let Some(tf) = type_filter {
        accounts.retain(|a| a.oath_type == tf);
    }
    if !show_hidden {
        accounts.retain(|a| !is_hidden_account(&a.name));
    }

    if accounts.is_empty() {
        if !single {
            println!("No accounts configured on token.");
        }
        return Ok(());
    }

    for acc in accounts {
        if single {
            println!("{}", acc.name);
        } else {
            let touch_str = if acc.touch_required { " [Touch]" } else { "" };
            println!(
                "{} ({}, {}){}",
                acc.name, acc.oath_type, acc.algorithm, touch_str
            );
        }
    }

    Ok(())
}

fn run_accounts_code(transport: &mut dyn TokenTransport, args: &[String]) -> Result<(), ManagerError> {
    let mut single = false;
    let mut password = None;
    let mut query = None;
    let mut show_hidden = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-s" | "--single" => single = true,
            "-p" | "--password" => {
                i += 1;
                if i < args.len() {
                    password = Some(args[i].clone());
                }
            }
            // ykman: `-H, --show-hidden` — "include hidden accounts". Used
            // to be a no-op flag named `--hover` here, which matched
            // nothing in real ykman and did nothing either; now implements
            // the same `issuer == "_hidden"` filter ykman's `is_hidden()`
            // uses (`yubikey-manager/ykman/oath.py`).
            "-H" | "--show-hidden" => show_hidden = true,
            arg if !arg.starts_with('-') && query.is_none() => {
                query = Some(arg.to_string());
            }
            _ => {}
        }
        i += 1;
    }

    let mut accounts = list_accounts(transport, password.as_deref())?;
    if !show_hidden {
        accounts.retain(|a| !is_hidden_account(&a.name));
    }
    if accounts.is_empty() {
        return Err(ManagerError::NotFound("No accounts configured on token.".into()));
    }

    let mut targets = accounts;
    if let Some(ref q) = query {
        let q_lower = q.to_ascii_lowercase();
        targets.retain(|a| a.name.to_ascii_lowercase().contains(&q_lower));
        if targets.is_empty() {
            return Err(ManagerError::NotFound(format!(
                "No account matching query '{q}' found."
            )));
        }
    }

    for acc in targets {
        if acc.touch_required && !single {
            println!("Touch sensor to approve OTP for '{}'...", acc.name);
        }
        match calculate_code(transport, &acc.name, None, 30, password.as_deref()) {
            Ok(calc) => {
                if single {
                    println!("{}", calc.code);
                } else {
                    let rem_str = calc
                        .remaining_seconds
                        .map(|r| format!(" ({}s remaining)", r))
                        .unwrap_or_default();
                    println!("{:<30} {}{}", calc.name, calc.code, rem_str);
                }
            }
            Err(e) => {
                if single {
                    return Err(e);
                } else {
                    eprintln!("{:<30} [FAILED: {}]", acc.name, e);
                }
            }
        }
    }

    Ok(())
}

fn run_accounts_add(transport: &mut dyn TokenTransport, args: &[String]) -> Result<(), ManagerError> {
    let mut name = None;
    let mut secret_str = None;
    let mut oath_type = OathType::Totp;
    let mut digits = 6u32;
    let mut algorithm = HashAlgorithm::Sha1;
    let mut period = 30u32;
    let mut counter = 0u64;
    let mut touch = false;
    let mut password = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--oath-type" => {
                i += 1;
                if i < args.len() {
                    oath_type = match args[i].to_ascii_uppercase().as_str() {
                        "TOTP" => OathType::Totp,
                        "HOTP" => OathType::Hotp,
                        other => {
                            return Err(ManagerError::InvalidInput(format!(
                                "Invalid oath-type '{other}'"
                            )))
                        }
                    };
                }
            }
            "-d" | "--digits" => {
                i += 1;
                if i < args.len() {
                    digits = args[i].parse().map_err(|_| "Invalid digits".to_string())?;
                }
            }
            "-a" | "--algorithm" => {
                i += 1;
                if i < args.len() {
                    algorithm = match args[i].to_ascii_uppercase().as_str() {
                        "SHA1" => HashAlgorithm::Sha1,
                        "SHA256" => HashAlgorithm::Sha256,
                        "SHA512" => HashAlgorithm::Sha512,
                        other => {
                            return Err(ManagerError::InvalidInput(format!(
                                "Invalid algorithm '{other}'"
                            )))
                        }
                    };
                }
            }
            // ykman: `-P, --period` (capital P). `-p` is `--password`
            // everywhere else in this subcommand tree (`access change`,
            // `accounts list/code/delete/rename/uri/import`) — this command
            // used to have the two swapped, the one place in the file that
            // broke that convention.
            "-P" | "--period" => {
                i += 1;
                if i < args.len() {
                    period = args[i].parse().map_err(|_| "Invalid period".to_string())?;
                }
            }
            "-c" | "--counter" => {
                i += 1;
                if i < args.len() {
                    counter = args[i].parse().map_err(|_| "Invalid counter".to_string())?;
                }
            }
            "-t" | "--touch" => touch = true,
            "-f" | "--force" => {}
            "-p" | "--password" => {
                i += 1;
                if i < args.len() {
                    password = Some(args[i].clone());
                }
            }
            arg if !arg.starts_with('-') => {
                if name.is_none() {
                    name = Some(arg.to_string());
                } else if secret_str.is_none() {
                    secret_str = Some(arg.to_string());
                }
            }
            _ => {}
        }
        i += 1;
    }

    let acc_name = name.ok_or_else(|| "Missing account NAME".to_string())?;
    let raw_secret = match secret_str {
        Some(s) => s,
        None => {
            print!("Enter Base32 Secret Key: ");
            io::stdout().flush().map_err(|e| e.to_string())?;
            let mut buf = String::new();
            io::stdin().read_line(&mut buf).map_err(|e| e.to_string())?;
            buf.trim().to_string()
        }
    };

    let secret_bytes = decode_base32(&raw_secret)
        .map_err(|e| format!("Invalid secret key (must be Base32): {e}"))?;

    put_account(
        transport,
        AddAccountOptions {
            name: acc_name.clone(),
            secret: secret_bytes,
            oath_type,
            algorithm,
            digits,
            period,
            counter,
            touch,
        },
        password.as_deref(),
    )?;

    println!("Account '{acc_name}' successfully added to token.");
    Ok(())
}

fn run_accounts_delete(transport: &mut dyn TokenTransport, args: &[String]) -> Result<(), ManagerError> {
    let mut query = None;
    let mut force = false;
    let mut password = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-f" | "--force" => force = true,
            "-p" | "--password" => {
                i += 1;
                if i < args.len() {
                    password = Some(args[i].clone());
                }
            }
            arg if !arg.starts_with('-') && query.is_none() => {
                query = Some(arg.to_string());
            }
            _ => {}
        }
        i += 1;
    }

    let target = query.ok_or_else(|| "Missing account query/name to delete".to_string())?;

    if !force {
        print!("Delete account '{target}' from token? [y/N]: ");
        io::stdout().flush().map_err(|e| e.to_string())?;
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .map_err(|e| e.to_string())?;
        let trimmed = input.trim().to_ascii_lowercase();
        if trimmed != "y" && trimmed != "yes" {
            println!("Delete cancelled.");
            return Ok(());
        }
    }

    delete_account(transport, &target, password.as_deref())?;
    println!("Account '{target}' deleted successfully.");
    Ok(())
}

fn run_accounts_rename(transport: &mut dyn TokenTransport, args: &[String]) -> Result<(), ManagerError> {
    let mut query = None;
    let mut new_name = None;
    let mut password = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-f" | "--force" => {}
            "-p" | "--password" => {
                i += 1;
                if i < args.len() {
                    password = Some(args[i].clone());
                }
            }
            arg if !arg.starts_with('-') => {
                if query.is_none() {
                    query = Some(arg.to_string());
                } else if new_name.is_none() {
                    new_name = Some(arg.to_string());
                }
            }
            _ => {}
        }
        i += 1;
    }

    let q = query.ok_or_else(|| "Missing account QUERY to rename".to_string())?;
    let n = new_name.ok_or_else(|| "Missing new NAME for account".to_string())?;

    rename_account(transport, &q, &n, password.as_deref())?;
    println!("Account '{q}' renamed to '{n}'.");
    Ok(())
}

fn run_accounts_uri(transport: &mut dyn TokenTransport, args: &[String]) -> Result<(), ManagerError> {
    let mut uri_str = None;
    let mut touch = false;
    let mut password = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-t" | "--touch" => touch = true,
            "-f" | "--force" => {}
            "-p" | "--password" => {
                i += 1;
                if i < args.len() {
                    password = Some(args[i].clone());
                }
            }
            arg if !arg.starts_with('-') && uri_str.is_none() => {
                uri_str = Some(arg.to_string());
            }
            _ => {}
        }
        i += 1;
    }

    let raw_uri = uri_str.ok_or_else(|| "Missing otpauth:// URI".to_string())?;
    let parsed = OtpAuthUri::parse(&raw_uri)?;
    let canonical = parsed.canonical_name();

    put_account(
        transport,
        AddAccountOptions {
            name: canonical.clone(),
            secret: parsed.secret,
            oath_type: parsed.oath_type,
            algorithm: parsed.algorithm,
            digits: parsed.digits,
            period: parsed.period,
            counter: parsed.counter,
            touch,
        },
        password.as_deref(),
    )?;

    println!("Imported account '{canonical}' from URI.");
    Ok(())
}

fn run_accounts_import(transport: &mut dyn TokenTransport, args: &[String]) -> Result<(), ManagerError> {
    let mut file_path = None;
    let mut touch = false;
    let mut password = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-t" | "--touch" => touch = true,
            "-f" | "--force" => {}
            "-p" | "--password" => {
                i += 1;
                if i < args.len() {
                    password = Some(args[i].clone());
                }
            }
            arg if !arg.starts_with('-') && file_path.is_none() => {
                file_path = Some(arg.to_string());
            }
            _ => {}
        }
        i += 1;
    }

    let path = file_path.ok_or_else(|| "Missing import FILE path".to_string())?;
    let content = fs::read_to_string(&path)
        .map_err(|e| format!("Failed to read import file '{path}': {e}"))?;

    let mut success_count = 0;
    let mut error_count = 0;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        match OtpAuthUri::parse(trimmed) {
            Ok(parsed) => {
                let name = parsed.canonical_name();
                match put_account(
                    transport,
                    AddAccountOptions {
                        name: name.clone(),
                        secret: parsed.secret,
                        oath_type: parsed.oath_type,
                        algorithm: parsed.algorithm,
                        digits: parsed.digits,
                        period: parsed.period,
                        counter: parsed.counter,
                        touch,
                    },
                    password.as_deref(),
                ) {
                    Ok(()) => {
                        println!("  [OK] Imported '{name}'");
                        success_count += 1;
                    }
                    Err(e) => {
                        eprintln!("  [FAIL] Failed to import '{name}': {e}");
                        error_count += 1;
                    }
                }
            }
            Err(e) => {
                eprintln!("  [SKIP] Invalid URI line: {e}");
                error_count += 1;
            }
        }
    }

    println!("\nImport complete: {success_count} accounts imported, {error_count} failed.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hidden_account_matches_ykmans_issuer_equals_underscore_hidden_rule() {
        assert!(is_hidden_account("_hidden:some-label"));
        // Not a prefix match — the issuer must be exactly "_hidden".
        assert!(!is_hidden_account("_hidden_but_not_quite:label"));
        assert!(!is_hidden_account("GitHub:alice"));
        // No colon at all: there is no issuer component, so not hidden.
        assert!(!is_hidden_account("no-issuer-here"));
    }
}
