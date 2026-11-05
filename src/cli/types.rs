#[derive(Parser)]
#[command(name = "isitsafe", version, about)]
struct Cli {
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize download-directory protections and verify the security configuration.
    #[command(name = "init", alias = "setup")]
    Init,
    /// Watch the configured download directory.
    Watch {
        /// Do not post interactive Windows review notifications.
        #[arg(long)]
        no_prompt: bool,
    },
    /// Open the native desktop workspace and ensure the download monitor is running.
    #[command(alias = "open")]
    Ui {
        /// Keep the monitor and UI server running without opening a browser window.
        #[arg(long)]
        background: bool,
    },
    /// Analyze one or more files immediately.
    Scan {
        paths: Vec<PathBuf>,
        #[arg(long)]
        json: bool,
        /// Do not post interactive Windows review notifications.
        #[arg(long)]
        no_prompt: bool,
    },
    /// Run the browser Native Messaging host.
    #[command(name = "native-host")]
    NativeHost,
    /// Install Native Messaging manifests for configured browser extension IDs.
    #[command(name = "install-host")]
    InstallHost,
    /// Manage quarantined files.
    Quarantine {
        #[command(subcommand)]
        command: QuarantineCommand,
    },
    /// Prune expired JSONL reports and report records.
    Reports {
        #[command(subcommand)]
        command: ReportsCommand,
    },
    /// Update signed YARA rules.
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
    /// Validate the effective configuration.
    #[command(name = "config")]
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Store the VirusTotal API key in Windows Credential Manager.
    #[command(name = "set-vt-key", hide = true)]
    SetVtKey { value: Option<String> },
    /// Internal Windows notification button handler.
    #[command(name = "handle-action", hide = true)]
    HandleAction { uri: String },
    /// Internal sandbox entry point.
    #[command(name = "__isitsafe_analysis_child", hide = true)]
    InternalChild,
}

#[derive(Subcommand)]
enum QuarantineCommand {
    List {
        #[arg(long)]
        search: Option<String>,
    },
    Restore {
        sha256: String,
        destination: PathBuf,
    },
    Prune,
}

#[derive(Subcommand)]
enum ReportsCommand {
    Prune,
}

#[derive(Subcommand)]
enum RulesCommand {
    Update,
}

#[derive(Subcommand)]
enum ConfigCommand {
    Validate,
    Path,
}
