# IsItSafe

IsItSafe watches a Windows download directory and reports what a downloaded file really contains. Executables, installers, scripts, documents, and archives are classified by content rather than filename, checked for polyglot/overlay content, and analyzed without executing any payload.

## Safety model

- The watcher never parses untrusted files in its own process.
- Analysis runs in a suspended child process assigned to a one-process Job Object and a zero-capability AppContainer.
- The child has no network capability and receives source bytes through an inherited pipe.
- VirusTotal, Windows Authenticode trust evaluation, and rule updates run only in the parent.
- Archive members are decompressed into bounded memory, analyzed, hashed, and discarded. They are never written to disk or executed.
- PE version resources and MSI/Inno metadata expose the declared product name, manufacturer, version, original filename, and certificate owner separately from the download filename.
- ZIP and RAR4/RAR5 containers are scanned recursively. RAR decoding is performed by the in-process `rar-codec` library rather than an external extractor.
- Files are considered ready only after an exclusive write-readiness handle has been acquired. Timeouts and protected volumes produce `Incomplete`.
- `BasicCheckOnly` files above 2 GiB receive streaming SHA-256, magic/trailer inspection, MOTW/ADS inspection, and VirusTotal hash lookup without unpacking.
- Initialization applies an inherited NTFS deny-execute rule to the download directory and the watcher re-verifies it on startup.
- Actionable results post a persistent Windows notification showing the verdict, file, hash, detected content, VirusTotal result when present, and the reasons for review. Its buttons are Keep, Quarantine, and Remove.

Static analysis cannot prove every runtime action. The report distinguishes facts, inference, unsupported behavior, and incomplete checks.

Encrypted RAR members, multivolume RAR sets, RAR 7 compression methods, and 7z extraction remain explicit unsupported or incomplete boundaries. RAR detection and ordinary RAR4/RAR5 extraction do not require process execution or a separate decompressor installation.

## Build

Windows 11 x64 and Rust 1.95 or newer are required.
The project is a Cargo workspace split into `isitsafe-config`,
`isitsafe-report`, `isitsafe-detect`, and `isitsafe-analysis` library crates,
with the watcher, sandbox, database, CLI, and desktop application in the root
`isitsafe` crate. Windows builds use the `rust-lld` linker bundled with the
Rust toolchain, and release builds use parallel code generation to keep local
iterations shorter.

```powershell
cargo build --release
```

Run the complete workspace checks:

```powershell
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

Optional YARA-X support:

```powershell
cargo build --release --features yara
```

Build the per-user Windows installer:

```powershell
.\scripts\build-installer.ps1
```

This requires [Inno Setup 6](https://jrsoftware.org/isinfo.php). The installer
is written to `dist\IsItSafe-<version>-windows-x64-setup.exe` together with its
SHA-256 checksum. The installer does not contain `config.toml` or a VirusTotal
API key.

The installed package includes `isitsafe-ui.exe`, a native eframe/egui Windows
application. It has a Review page for questionable downloads, a Quarantine page
with hash-verified restore actions, and a stored component-inventory view that
shows detected software identities and highlights risky embedded files. The
Settings page controls the active monitor, sign-in startup, the watched download
directory, the quarantine location on any writable drive, and an optional
`Is It Safe?` Explorer file context menu. The context-menu action scans only the
selected file in memory and opens its stored report in the desktop app. Its custom
captionless title strip provides
drag, minimize, maximize/restore, and close controls. The UI reads the local
SQLite state directly and does not start an HTTP server or require WebView2.
Run `isitsafe-ui.exe --background` to start the monitor without opening a
window. The installer offers sign-in monitoring as an initial option; the
Settings page can change or disable it later.

When YARA support is enabled, built-in rules run in the sandbox. Signed remote rule packs can be installed with `isitsafe.exe rules update` after configuring `yara.remote_manifest_url` and `yara.public_key_base64`. The manifest payload is Ed25519-signed and every downloaded rule file is SHA-256 verified before use.

## Configuration

The default configuration is created at:

```text
%APPDATA%\IsItSafe\config.toml
```

When running a build from this repository, an ignored project-root `config.toml`
is selected automatically. Installed builds continue to use the `%APPDATA%`
configuration.

Use a custom file with `--config`:

```powershell
.\target\release\isitsafe.exe --config .\config.example.toml config validate
```

The default download directory is `%USERPROFILE%\Downloads`. Important settings include:

- `limits.snapshot_max_bytes`: maximum in-memory deep-analysis snapshot.
- `limits.basic_check_threshold_bytes`: threshold for BasicCheckOnly.
- `limits.lock_acquisition_timeout_ms`: maximum wait for an exclusive readiness handle.
- `security.block_execution_in_download_dir`: apply and verify the inherited download-directory execute denial.
- `interaction.enabled`: post the Windows Keep/Quarantine/Remove review notification for actionable results.
- `runtime.monitor_enabled`: whether the desktop app keeps background monitoring active.
- `runtime.start_at_login`: mirror of the per-user Windows sign-in registration managed by Settings.
- `runtime.context_menu_enabled`: mirror of the per-user `Is It Safe?` Explorer file context-menu registration.
- `storage.quarantine_dir`: folder that receives new quarantine entries; existing entries remain at their recorded paths.
- `events.temp_extensions`: downloader temporary extensions.
- `events.temp_rename_grace_ms`: time before a never-renamed temporary file emits `TempOnly`.
- `virus_total.requests_per_minute`: global persistent VirusTotal limit.
- `policy.quarantine_enabled`: move confirmed malicious files into recoverable quarantine.
- `policy.quarantine_retention_days`: keep quarantine entries searchable before pruning.

See `config.example.toml` for the full schema.

## Initialization and Downloads execution barrier

Run initialization once after installing or changing the download directory:

```powershell
.\target\release\isitsafe.exe init
```

The command applies the current user's `(OI)(IO)(DENY)(X)` ACE to
`download_dir`, then reads the directory DACL back and verifies that the
inherited deny-execute ACE exists. `watch` repeats this check at startup. The
deny affects native executables and DLLs without denying directory traversal.
It is inherited by existing and future files, including files in
subdirectories.

To remove the rule:

```powershell
$downloads = Join-Path $env:USERPROFILE 'Downloads'
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
icacls $downloads /remove:d "*${sid}"
```

This is a defense-in-depth barrier, not a sandbox. It does not prevent copying
the file elsewhere, and interpreted scripts or document viewers may still read
the file depending on how they are launched. A file must be moved to a trusted
location before it can be executed.

## VirusTotal

Hash lookups use the VirusTotal v3 API. For normal installed use, store the key in
Windows Credential Manager:

```powershell
.\target\release\isitsafe.exe set-vt-key
```

Paste the key when prompted. For local development, a project-root `config.toml`
may contain only the personal override:

```toml
[virus_total]
api_key = "your-key"
```

`config.toml` is ignored by Git and is selected automatically by repository
builds. It may also be passed explicitly with `--config .\config.toml`. The API
key is redacted from debug output and is never written back when the
configuration is serialized. `VIRUSTOTAL_API_KEY` is also accepted for CI or
temporary use. Uploads are disabled. Unknown, missing, throttled, or offline
reputation results remain explicit and are never converted to "clean."

## Usage

Open the native window:

```powershell
.\target\release\isitsafe-ui.exe
```

The Review page groups unresolved files by risk and shows the recorded reasons.
Quarantine moves a file immediately after reacquiring the write lock and
verifying its SHA-256. Restore requires confirmation and verifies the hash again;
files restored to Downloads remain covered by the deny-execute rule.

Watch downloads:

```powershell
.\target\release\isitsafe.exe watch
```

Actionable results post a Windows toast notification. `init` creates the
per-user Start-menu shortcut and AppUserModelID required for an unpackaged
desktop app to appear in Notification Center. `Keep` leaves the original
in place, `Quarantine` moves it to the recoverable quarantine, and `Remove`
permanently deletes it after a fresh exclusive-lock hash check. The notification
remains in Windows Notification Center and its buttons work through the
per-user `isitsafe-action` handler registered by `init`. If notification
delivery fails, the configured policy fallback applies; confirmed-malicious
files remain quarantined by default. Windows Do Not Disturb may suppress the
banner; the notification remains visible under Notification Center.

Analyze files immediately:

```powershell
.\target\release\isitsafe.exe scan .\downloads\setup.exe --json
```

Use `--no-prompt` with `watch` or `scan` for unattended operation. `scan --json`
never posts a notification and therefore uses the configured policy fallback.

Inspect quarantine:

```powershell
.\target\release\isitsafe.exe quarantine list --search typora
.\target\release\isitsafe.exe quarantine restore <sha256> C:\Users\me\Downloads\restored.exe
.\target\release\isitsafe.exe quarantine prune
```

Quarantine keeps the original filename visible with a short hash suffix, for
example `setup.exe.aaaaaaaaaaaa.quarantined`. Entries are executable-denied and
retained for 30 days by default so they can be inspected or restored before
expiry.

Prune retained reports:

```powershell
.\target\release\isitsafe.exe reports prune
```

JSON reports are stored under `%LOCALAPPDATA%\IsItSafe\reports` as daily JSONL files. Reports and SQLite state retain for 30 days by default.

## Browser origin tracking

Extension sources are under `extension\chromium` and `extension\firefox`.

1. Load the unpacked Chromium extension from `extension\chromium` in Chrome or Edge, or the Firefox extension from `extension\firefox`.
2. Record the resulting extension ID in `origin.chrome_extension_ids` or `origin.firefox_extension_ids`.
3. Run:

```powershell
.\target\release\isitsafe.exe install-host
```

The installer registers the `isitsafe-native-host` executable for Chrome, Edge, and Firefox with the configured extension IDs. Browser referrers are best effort because browsers may withhold them.

## Exit states and boundaries

Verdicts are `Malicious`, `Suspicious`, `ReviewRequired`, `Unverified`, `Limited`, `Incomplete`, `BasicCheckOnly`, and `NoHighRiskFound`. Every report also includes detailed signature, revocation, lock, MOTW, threshold, child-execution, and resource-boundary fields.

`NoHighRiskFound` means completed static checks found no high-risk evidence; it is not a runtime safety proof.

## Development checks

```powershell
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo check --features yara
```

The integration suite launches the real AppContainer child and verifies both network and process-creation probes are denied. Fuzz targets are provided under `fuzz/`.

