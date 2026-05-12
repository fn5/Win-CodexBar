use clap::Parser;
use codexbar::{
    cli::{self, Cli, Commands, exit_codes},
    logging,
};

fn launch_log_path() -> std::path::PathBuf {
    std::env::temp_dir().join("codexbar_launch.log")
}

fn log_launch_start() {
    // Keep this log intentionally sparse: no provider identifiers, no WSL details.
    let log_path = launch_log_path();
    let arg_count = std::env::args().count();
    let _ = std::fs::write(
        &log_path,
        format!(
            "main() started at {:?}\narg_count={}\n",
            std::time::SystemTime::now(),
            arg_count
        ),
    );
}

fn log_launch_exit(exit_code: i32) {
    let log_path = launch_log_path();
    let _ = std::fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .and_then(|mut f| {
            use std::io::Write;
            writeln!(f, "Exiting with code: {}", exit_code)
        });
}

fn main() {
    log_launch_start();

    let exit_code = run();
    log_launch_exit(exit_code);

    std::process::exit(exit_code);
}

fn run() -> i32 {
    let cli = Cli::parse();

    // Initialize logging
    if let Err(e) = logging::init(cli.verbose, cli.json_output) {
        eprintln!("Failed to initialize logging: {}", e);
        return exit_codes::UNEXPECTED_FAILURE;
    }

    // Create tokio runtime for async commands
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Failed to create runtime: {}", e);
            return exit_codes::UNEXPECTED_FAILURE;
        }
    };

    match cli.command {
        Some(Commands::Usage(args)) => rt.block_on(async {
            match cli::usage::run(args).await {
                Ok(()) => exit_codes::SUCCESS,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    categorize_error(&e)
                }
            }
        }),
        Some(Commands::Cost(args)) => rt.block_on(async {
            match cli::cost::run(args).await {
                Ok(()) => exit_codes::SUCCESS,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    categorize_error(&e)
                }
            }
        }),
        Some(Commands::Autostart(args)) => rt.block_on(async {
            match cli::autostart::run(args).await {
                Ok(()) => exit_codes::SUCCESS,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    exit_codes::UNEXPECTED_FAILURE
                }
            }
        }),
        Some(Commands::Account(args)) => rt.block_on(async {
            match cli::account::run(args).await {
                Ok(()) => exit_codes::SUCCESS,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    exit_codes::UNEXPECTED_FAILURE
                }
            }
        }),
        Some(Commands::Config(args)) => rt.block_on(async {
            match cli::config::run(args).await {
                Ok(()) => exit_codes::SUCCESS,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    exit_codes::UNEXPECTED_FAILURE
                }
            }
        }),
        None => {
            // The egui menubar shell has been retired; the desktop UI lives in
            // apps/desktop-tauri. The CLI binary now requires an explicit subcommand.
            eprintln!(
                "codexbar is now CLI-only. Run a subcommand (e.g. `codexbar usage -p claude`) \
                 or launch the Tauri desktop shell via `apps/desktop-tauri`.\n\
                 Use `codexbar --help` for the full list of subcommands."
            );
            exit_codes::USAGE_ERROR
        }
    }
}

/// Categorize an error into the appropriate exit code
fn categorize_error(e: &anyhow::Error) -> i32 {
    let msg = e.to_string().to_lowercase();

    if msg.contains("not installed") || msg.contains("not found") || msg.contains("binary") {
        exit_codes::PROVIDER_MISSING
    } else if msg.contains("parse") || msg.contains("format") || msg.contains("invalid") {
        exit_codes::PARSE_ERROR
    } else if msg.contains("timeout") || msg.contains("timed out") {
        exit_codes::CLI_TIMEOUT
    } else {
        exit_codes::UNEXPECTED_FAILURE
    }
}
