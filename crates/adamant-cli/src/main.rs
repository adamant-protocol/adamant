//! `adamant-cli` binary entry point. Dispatches to the
//! library-level [`adamant_cli::execute`] per the parsed
//! [`adamant_cli::Command`].

#![forbid(unsafe_code)]

use adamant_cli::{execute, parse_args, HELP_TEXT};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = parse_args(&args) else {
        eprintln!("{HELP_TEXT}");
        std::process::exit(if args.is_empty() { 0 } else { 2 });
    };
    match execute(&cmd) {
        Ok(out) => {
            print!("{}", out.stdout);
        }
        Err(e) => {
            eprintln!("adamant-cli error: {e}");
            std::process::exit(1);
        }
    }
}
