use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

use winewarden_core::trust::TrustTier;
use winewarden_core::types::LiveMonitorConfig;

mod commands;
mod tui;

#[derive(Parser, Debug)]
#[command(
    name = "winewarden",
    version,
    about = "Calm protection for Windows games on Linux"
)]
struct Cli {
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Init {
        #[arg(long)]
        path: Option<PathBuf>,
        #[arg(long)]
        force: bool,
    },
    Run {
        #[arg(long)]
        prefix: Option<PathBuf>,
        #[arg(long)]
        event_log: Option<PathBuf>,
        #[arg(long)]
        trust: Option<TrustTier>,
        #[arg(long)]
        no_run: bool,
        #[arg(long)]
        pirate_safe: bool,
        #[arg(long)]
        live: bool,
        #[arg(long)]
        live_fs: bool,
        #[arg(long)]
        live_proc: bool,
        #[arg(long)]
        live_net: bool,
        #[arg(long, default_value_t = 250)]
        poll_ms: u64,
        #[arg(long)]
        daemon: bool,
        executable: PathBuf,
        args: Vec<String>,
    },
    Report {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Trust {
        #[command(subcommand)]
        action: TrustCommand,
    },
    Prefix {
        #[command(subcommand)]
        action: PrefixCommand,
    },
    Status {
        executable: Option<PathBuf>,
        #[arg(long)]
        daemon: bool,
    },
    Daemon {
        #[command(subcommand)]
        action: DaemonCommand,
    },
    Config {
        #[arg(long)]
        print: bool,
    },
    /// Launch interactive TUI dashboard
    Monitor {
        /// Session ID to monitor (optional, starts new if not provided)
        #[arg(long)]
        session: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum TrustCommand {
    Get {
        executable: PathBuf,
    },
    Set {
        executable: PathBuf,
        tier: TrustTier,
    },
}

#[derive(Subcommand, Debug)]
enum PrefixCommand {
    Scan { prefix: PathBuf },
    Snapshot { prefix: PathBuf },
}

#[derive(Subcommand, Debug)]
enum DaemonCommand {
    Start {
        #[arg(long)]
        socket: Option<PathBuf>,
        #[arg(long)]
        pid: Option<PathBuf>,
    },
    Stop {
        #[arg(long)]
        pid: Option<PathBuf>,
    },
    Ping {
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    Status {
        #[arg(long)]
        socket: Option<PathBuf>,
    },
    SocketPath,
    PidPath,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init { path, force } => init_config(path, force),
        Commands::Run {
            prefix,
            event_log,
            trust,
            no_run,
            pirate_safe,
            live,
            live_fs,
            live_proc,
            live_net,
            poll_ms,
            daemon,
            executable,
            args,
        } => commands::run::execute(commands::run::RunInputs {
            config_path: cli.config,
            prefix,
            event_log,
            trust_override: trust,
            no_run,
            pirate_safe,
            executable,
            args,
            live_monitor: build_live_monitor(live, live_fs, live_proc, live_net, poll_ms),
            use_daemon: daemon,
        }),
        Commands::Report { input, json } => commands::report::execute(&input, json),
        Commands::Trust { action } => {
            let action = match action {
                TrustCommand::Get { executable } => {
                    commands::trust::TrustAction::Get { executable }
                }
                TrustCommand::Set { executable, tier } => {
                    commands::trust::TrustAction::Set { executable, tier }
                }
            };
            commands::trust::execute(action)
        }
        Commands::Prefix { action } => {
            let action = match action {
                PrefixCommand::Scan { prefix } => commands::prefix::PrefixAction::Scan { prefix },
                PrefixCommand::Snapshot { prefix } => {
                    commands::prefix::PrefixAction::Snapshot { prefix }
                }
            };
            commands::prefix::execute(action)
        }
        Commands::Status { executable, daemon } => commands::status::execute(executable, daemon),
        Commands::Daemon { action } => {
            let action = match action {
                DaemonCommand::Start { socket, pid } => {
                    commands::daemon::DaemonAction::Start { socket, pid }
                }
                DaemonCommand::Stop { pid } => commands::daemon::DaemonAction::Stop { pid },
                DaemonCommand::Ping { socket } => commands::daemon::DaemonAction::Ping { socket },
                DaemonCommand::Status { socket } => {
                    commands::daemon::DaemonAction::Status { socket }
                }
                DaemonCommand::SocketPath => commands::daemon::DaemonAction::SocketPath,
                DaemonCommand::PidPath => commands::daemon::DaemonAction::PidPath,
            };
            commands::daemon::execute(action)
        }
        Commands::Config { print } => {
            if print {
                commands::config::print_effective(cli.config)
            } else {
                Ok(())
            }
        }
        Commands::Monitor { session: _ } => {
            // Launch the TUI
            tui::run_tui()
        }
    }
}

fn init_config(path: Option<PathBuf>, force: bool) -> Result<()> {
    let paths = winewarden_core::config::ConfigPaths::resolve()?;
    let config_path = path.unwrap_or(paths.config_path);
    if config_path.exists() && !force {
        return Err(anyhow::anyhow!(
            "Config already exists at {} (use --force to overwrite)",
            config_path.display()
        ));
    }
    let config = winewarden_core::config::Config::default_config();
    config.save(&config_path)?;
    println!("Config written to {}", config_path.display());
    Ok(())
}

fn build_live_monitor(
    live: bool,
    live_fs: bool,
    live_proc: bool,
    live_net: bool,
    poll_ms: u64,
) -> Option<LiveMonitorConfig> {
    let fs = live || live_fs;
    let proc = live || live_proc;
    let net = live || live_net;
    if fs || proc || net {
        Some(LiveMonitorConfig {
            fs,
            proc,
            net,
            poll_interval_ms: poll_ms,
        })
    } else {
        None
    }
}
