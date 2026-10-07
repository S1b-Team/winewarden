# WineWarden

<p align="center">
  <img src="assets/ui/banner.png" alt="WineWarden banner" width="100%" />
</p>

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&pause=1000&color=7CFC00&center=true&vCenter=true&width=900&lines=Play+Windows+games+on+Linux;without+trusting+random+executables+with+your+system." alt="WineWarden tagline" />
</p>

<p align="center">
  <img alt="CI" src="https://github.com/ind4skylivey/winewarden/actions/workflows/ci.yml/badge.svg" />
  <img alt="Security Audit" src="https://github.com/ind4skylivey/winewarden/actions/workflows/security-audit.yml/badge.svg" />
  <img alt="License" src="https://img.shields.io/github/license/ind4skylivey/winewarden" />
  <img alt="Rust" src="https://img.shields.io/badge/rust-1.75%2B-ff7a18" />
  <img alt="Platform" src="https://img.shields.io/badge/platform-linux-4caf50" />
  <img alt="Tests" src="https://img.shields.io/badge/tests-44%20passing-brightgreen" />
  <img alt="Status" src="https://img.shields.io/badge/status-beta-ff9800" />
</p>

> "Play Windows games on Linux without trusting random executables with your system."

WineWarden is a calm, always-on protection layer for Wine, Proton, Lutris, and Steam. It provides **real-time filesystem virtualization**, **network monitoring**, **process sandboxing**, and **dynamic trust scoring** — all through an elegant terminal interface.

```
==[ W I N E W A R D E N ]===================================================
calm by design · silent by default · strict by choice
==============================================================================
```

## ✨ What's New (Recently Implemented)

### 🛡️ Filesystem Virtualization (Phase 1)
- **Mount Namespace Isolation**: Creates private filesystem namespaces with bind-mount virtualization
- **Path Mapping**: Prefix-based redirects (e.g., `${HOME}` → `${DATA_DIR}/virtual/home`)
- **Landlock Sandbox**: Kernel-level access control for defense-in-depth

### 🌐 Network Awareness (Phase 2)
- **DNS Packet Parser**: Full parsing of DNS queries/responses (A, AAAA, CNAME, MX, NS, TXT, SRV)
- **Destination Tracking**: Monitors outbound connections and unique destinations
- **Network Telemetry**: Tracks connection success rates, protocols, and ports
- **Real-time Interception**: Seccomp-based syscall interception for connect/bind

### 🔒 Process Security (Phase 3)
- **Process Policy Engine**: Wildcard pattern matching for allowed/blocked processes
- **Shell & Script Blocking**: Prevents execution of bash, powershell, Python scripts, etc.
- **Child Process Limits**: Configurable maximum process count (prevents fork bombs)
- **Dynamic Trust Scoring**: 0-100 score based on runtime behavior with trend analysis

### 📊 Interactive TUI Dashboard (Phase 4)
- **Real-time Monitoring**: Live session statistics with 20 FPS rendering
- **5 Interactive Screens**:
  - 📈 **Dashboard**: Session timer, trust gauge, event rate, denial statistics
  - 🎯 **Trust**: Current score, recommended tier, history sparkline graph
  - 🌐 **Network**: Active connections table, DNS queries with resolved IPs
  - ⚙️ **Processes**: Process list with status indicators (●/⏸/✗) and runtime
  - 📋 **Events**: Filterable event log with timestamp, kind, target, notes
- **Keyboard Navigation**: Tab/arrows for screens, `/` to filter, Q to quit

## 🚀 Quick Start

```bash
# Build from source
cargo build --release

# Install binaries
cargo install --path crates/winewarden-cli
cargo install --path crates/winewarden-daemon

# Initialize configuration
winewarden init

# Launch the TUI dashboard (NEW!)
winewarden monitor

# Run a game with full protection
winewarden run /path/to/game.exe -- -arg1 -arg2

# Run via daemon for background monitoring
winewarden daemon start
winewarden run --daemon /path/to/game.exe
```

## 🎮 Interactive TUI

Launch the real-time monitoring dashboard:

```bash
winewarden monitor
```

**Keyboard Controls:**
| Key | Action |
|-----|--------|
| `Tab` / `→` | Next screen |
| `Shift+Tab` / `←` | Previous screen |
| `1-5` | Jump to specific screen |
| `Q` | Quit |
| `P` | Pause/Resume monitoring |
| `/` | Filter events (Events screen) |
| `↑↓` | Scroll events |
| `Home/End` | Jump to start/end |
| `Esc` | Clear filter |

## 🛡️ Security Features

### Active Enforcement
WineWarden now uses **kernel-level security mechanisms**:

- **Landlock LSM**: Filesystem sandbox blocking access to personal files (`$HOME`, `.ssh`, `.gnupg`)
- **Seccomp Notify**: Real-time syscall interception for network calls (`connect`, `bind`)
- **Mount Namespaces**: Private filesystem views with bind-mount virtualization
- **Path Virtualization**: Automatic redirect of sensitive paths to isolated locations

### System Requirements
- **Linux Kernel 5.11+** (for Landlock and Seccomp Notify)
- **libseccomp** development headers:
  - Debian/Ubuntu: `sudo apt install libseccomp-dev`
  - Fedora: `sudo dnf install libseccomp-devel`
  - Arch: `sudo pacman -S libseccomp`

## 📋 Command Reference

### Core Commands

```bash
# Initialize config
winewarden init

# Run a game
winewarden run /path/to/game.exe -- -arg1 -arg2

# Run with live monitoring
winewarden run --live-fs --live-proc --live-net /path/to/game.exe

# Launch TUI dashboard (NEW!)
winewarden monitor

# View reports
winewarden report --input ~/.local/share/winewarden/reports/<id>.json
```

### Trust Management

```bash
# Check trust tier
winewarden trust get /path/to/game.exe

# Set trust tier (green/yellow/red)
winewarden trust set /path/to/game.exe green

# View trust status
winewarden status /path/to/game.exe
```

### Prefix Hygiene

```bash
# Scan prefix for issues
winewarden prefix scan /path/to/prefix

# Create snapshot
winewarden prefix snapshot /path/to/prefix
```

### Daemon Mode

```bash
# Start background daemon
winewarden daemon start

# Run through daemon
winewarden run --daemon /path/to/game.exe

# Check daemon status
winewarden daemon status
winewarden daemon ping
```

## ⚙️ Configuration

Configuration is TOML-based and human-readable:

```toml
# ~/.config/winewarden/config.toml

[winewarden]
enabled = true
no_prompts_during_gameplay = true
emergency_only = true

[trust]
default_tier = "yellow"
auto_promote = true
promotion_after_runs = 3

[process]
allowed_patterns = ["wine*", "*.exe"]
blocked_patterns = ["*nc*", "*powershell*", "*cmd.exe*"]
max_child_processes = 50
allow_shell_execution = false
allow_script_execution = false

[network]
mode = "observe"
dns_awareness = true
destination_monitoring = true

[sacred_zones]
[[sacred_zones.zones]]
label = "SSH keys"
path = "${HOME}/.ssh"
action = "deny"

[[sacred_zones.zones]]
label = "Home directory"
path = "${HOME}"
action = "redirect"
redirect_to = "${DATA_DIR}/virtual/home"
```

**Environment Variables:**
- `WINEWARDEN_REDIRECT_MAP` - Custom path mappings (e.g., `"${HOME}:/virtual/home,/tmp:/virtual/tmp"`)
- `WINEWARDEN_SOCKET` - Custom daemon socket path
- `WINEWARDEN_PID` - Custom PID file path

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        WineWarden CLI                        │
│                    (TUI + Commands)                          │
└────────────────────┬────────────────────────────────────────┘
                     │
    ┌────────────────┼────────────────┐
    │                │                │
    ▼                ▼                ▼
┌─────────┐    ┌──────────┐    ┌──────────┐
│ Monitor │◄──►│ Policy   │◄──►│ NetCompat│
│ (Sandbox)│    │ Engine   │    │ (DNS/Net)│
└────┬────┘    └────┬─────┘    └────┬─────┘
     │              │               │
     ▼              ▼               ▼
┌─────────┐    ┌──────────┐    ┌──────────┐
│Landlock │    │ Process  │    │ Telemetry│
│Mount NS │    │ Rules    │    │ Tracking │
│Seccomp  │    │ Trust    │    │          │
└─────────┘    │ Scoring  │    └──────────┘
               └──────────┘
```

### Crate Structure

- **`winewarden-core`**: Shared types, config, trust store, IPC
- **`winewarden-cli`**: Main CLI binary with TUI
- **`winewarden-daemon`**: Background daemon for persistent monitoring
- **`monitor`**: Sandbox implementation (Landlock, Seccomp, Mount NS)
- **`policy-engine`**: Decision engine with process rules and trust scoring
- **`net-compat`**: DNS parsing, destination tracking, network telemetry
- **`prefix-manager`**: Prefix hygiene, snapshots, quarantine
- **`reporting`**: Report generation (human + JSON)
- **`runner`**: Safe command construction and execution

## 📊 Trust Tiers

| Tier | Color | Behavior |
|------|-------|----------|
| **Green** | 🟢 | Trusted, minimal restrictions |
| **Yellow** | 🟡 | Unknown, balanced protection (default) |
| **Red** | 🔴 | Untrusted, strict isolation |

Trust scores (0-100) are calculated dynamically based on:
- Sensitive path access attempts
- Network destination diversity
- Child process spawning
- Denied access attempts
- Behavior consistency over time

## 🎮 Integration Examples

### Steam (Launch Options)
```bash
winewarden run -- %command%
```

### Lutris (System Options)
```bash
# Pre-launch script
winewarden run

# Or full path
winewarden run /path/to/game.exe
```

### Heroic Games Launcher
Configure the wrapper in game settings to use `winewarden run`.

## 📈 Flow Diagrams

### Execution Flow
```
winewarden run
       │
       ▼
┌──────────────┐
│  Mount NS    │──► Create private filesystem namespace
│  Setup       │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  Landlock    │──► Apply filesystem sandbox rules
│  Sandbox     │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  Seccomp     │──► Install syscall interception
│  Filter      │
└──────┬───────┘
       │
       ▼
┌──────────────┐     ┌──────────────┐
│  Monitor     │◄───►│  Policy      │
│  (Events)    │     │  Engine      │
└──────┬───────┘     └──────────────┘
       │
       ▼
┌──────────────┐
│  TUI/        │──► Real-time visualization
│  Reporting   │
└──────────────┘
```

### Policy Decision Flow
```
Access Attempt
       │
       ▼
┌──────────────┐
│ Sacred Zone? │──► Yes ──► Deny / Redirect / Virtualize
└──────┬───────┘
       │ No
       ▼
┌──────────────┐
│ Process      │──► Check patterns, limits, shell detection
│ Policy?      │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Network      │──► Check destinations, DNS, telemetry
│ Policy?      │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  Allow + Log │──► Update trust score, record telemetry
└──────────────┘
```

## 🧪 Testing

```bash
# Run all tests
cargo test --all

# Run specific crate tests
cargo test -p monitor
cargo test -p policy-engine
cargo test -p net-compat

# Run with coverage
cargo tarpaulin --all
```

## 📚 Documentation

- [docs/vision.md](docs/vision.md) - Project vision and goals
- [docs/threat-model.md](docs/threat-model.md) - Security threat model
- [docs/winewarden-mode.md](docs/winewarden-mode.md) - WineWarden mode philosophy
- [docs/trust-tiers.md](docs/trust-tiers.md) - Trust tier system
- [docs/sacred-zones.md](docs/sacred-zones.md) - Sacred zones concept
- [docs/prefix-hygiene.md](docs/prefix-hygiene.md) - Prefix maintenance
- [docs/networking.md](docs/networking.md) - Network monitoring
- [docs/pirate-safe-mode.md](docs/pirate-safe-mode.md) - Pirate-safe mode
- [docs/reports.md](docs/reports.md) - Report format
- [docs/configuration.md](docs/configuration.md) - Configuration reference
- [docs/architecture.md](docs/architecture.md) - System architecture
- [docs/glossary.md](docs/glossary.md) - Terminology

## 🤝 Contributing

Contributions are welcome! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## 📝 License

This project is proprietary software. All rights reserved.

Copyright (c) 2025 S1BGr0up (https://github.com/S1b-Team)  
Author: ind4skylivey (https://github.com/ind4skylivey)

See the [LICENSE](LICENSE) file for full terms. Commercial licenses and permissions are available upon request.

## 🙏 Acknowledgments

- Landlock LSM team for the sandboxing technology
- The Wine and Proton projects for Windows compatibility
- The Rust community for excellent tools and libraries

---

<p align="center">
  <strong>Calm by design · Silent by default · Strict by choice</strong>
</p>
