//! `cryptick-piv`: Provisioning tool for Cryptick Token PIV slots.
//!
//! Generates EC P-256 keys on token slots 9A (PIV Authentication) and 9D (Key Management),
//! constructs self-signed X.509 v3 certificates, wraps them into SP 800-73-5 certificate
//! containers (`0x53`), and transmits them using chained `PUT DATA` short APDUs.

use std::env;
use std::process::ExitCode;

use piv::cli::{help_text, parse_args, run_provision, CliCommand};

fn main() -> ExitCode {
    let command = match parse_args(env::args().skip(1)) {
        Ok(cmd) => cmd,
        Err(err) => {
            eprintln!("Error: {err}\n");
            eprintln!("{}", help_text());
            return ExitCode::FAILURE;
        }
    };

    match command {
        CliCommand::Help => {
            println!("{}", help_text());
            ExitCode::SUCCESS
        }
        CliCommand::Version => {
            println!("cryptick-piv 0.1.0");
            ExitCode::SUCCESS
        }
        CliCommand::Provision(opts) => match run_provision(opts) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("Provisioning error: {err}");
                ExitCode::FAILURE
            }
        },
    }
}
