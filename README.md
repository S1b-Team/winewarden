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
  <img alt="Release" src="https://github.com/ind4skylivey/winewarden/actions/workflows/release.yml/badge.svg" />
  <img alt="License" src="https://img.shields.io/github/license/ind4skylivey/winewarden" />
  <img alt="Rust" src="https://img.shields.io/badge/rust-1.75%2B-ff7a18" />
  <img alt="Platform" src="https://img.shields.io/badge/platform-linux-4caf50" />
  <img alt="Status" src="https://img.shields.io/badge/status-pre--alpha-ff5252" />
</p>

"Play Windows games on Linux without trusting random executables with your system."

WineWarden is a calm, always-on protection layer for Wine, Proton, Lutris, and Steam. It is not an antivirus. It does not moralize. It exists so you can play without anxiety.

```
==[ W I N E W A R D E N ]===================================================
calm by design · silent by default · strict by choice
===========================================================================
```

## What It Is

- WineWarden Mode: silent protection with no prompts during gameplay
- Trust Tiers: clear reassurance signals (Green, Yellow, Red)
- Sacred Zones: protect the places games should never need
- Prefix Hygiene: keep prefixes clean and stable over time
- Network Safety: observe without breaking multiplayer
- Pirate-Safe Mode: stronger isolation with zero judgment
- Human Reports: short, calm summaries after each run

## Why It Feels Different

- Secure by default
- Easy to relax
- Hard to break accidentally
- No popups mid-game
- No shame, no fear

## Quick Start

```bash
# Initialize config
winewarden init

# Run a game quietly (no prompts during gameplay)
winewarden run /path/to/game.exe -- -arg1 -arg2

# Run with a provided event log (JSONL of AccessAttempt)
winewarden run /path/to/game.exe --event-log tests/fixtures/events.jsonl --no-run

# View a report
winewarden report --input ~/.local/share/winewarden/reports/<id>.json
```

## Interactive Guide (Full Tour)

<details>
<summary><strong>[+] 1) Install from source</strong></summary>

```bash
cargo build --release
cargo install --path crates/winewarden-cli
cargo install --path crates/winewarden-daemon
```
```
Tip: use a dedicated Rust toolchain for reproducible builds.
```
</details>

<details>
<summary><strong>[+] 2) Initialize config</strong></summary>

```bash
winewarden init
```

Config file lives at: `~/.config/winewarden/config.toml`
```
Config path: ~/.config/winewarden/config.toml
Reports:     ~/.local/share/winewarden/reports/
```
</details>

<details>
<summary><strong>[+] 3) Run a game (direct)</strong></summary>

```bash
winewarden run /path/to/game.exe -- -arg1 -arg2
```
```
No prompts during gameplay. Summary after exit.
```
</details>

<details>
<summary><strong>[+] 4) Run via daemon (background mode)</strong></summary>

```bash
winewarden daemon start
winewarden run --daemon /path/to/game.exe -- -arg1 -arg2
winewarden daemon status
```
```
Daemon uses a local Unix socket with user-only access.
```
</details>

<details>
<summary><strong>[+] 5) Live monitoring (optional)</strong></summary>

```bash
# All live monitors
winewarden run --live /path/to/game.exe -- -arg1 -arg2

# Or pick specific channels
winewarden run --live-fs --live-proc --live-net --poll-ms 250 /path/to/game.exe -- -arg1
```
```
Live monitoring observes only; it does not interrupt gameplay.
```
</details>

<details>
<summary><strong>[+] 6) Trust tiers (pin or relax)</strong></summary>

```bash
# Inspect trust tier for an executable
winewarden trust get /path/to/game.exe

# Pin a tier
winewarden trust set /path/to/game.exe green
```
```
Green = known safe behavior
Yellow = unknown but non-hostile
Red = strict isolation
```
</details>

<details>
<summary><strong>[+] 7) Prefix hygiene</strong></summary>

```bash
winewarden prefix scan /path/to/prefix
winewarden prefix snapshot /path/to/prefix
```
```
Prefix hygiene keeps the ecosystem stable over time.
```
</details>

<details>
<summary><strong>[+] 8) Reports (human + JSON)</strong></summary>

```bash
winewarden report --input ~/.local/share/winewarden/reports/<id>.json
winewarden report --input ~/.local/share/winewarden/reports/<id>.json --json
```
```
Human summaries by default. Structured JSON on demand.
```
</details>

<details>
<summary><strong>[+] 9) Integration snippets (real paths)</strong></summary>

```bash
# Steam (Launch Options):
winewarden run -- %command%

# Steam (example Windows game path):
~/.steam/steam/steamapps/common/SomeGame/SomeGame.exe

# Proton prefix (example, for reference only):
~/.steam/steam/steamapps/compatdata/123456/pfx/drive_c/

# Lutris (example prefix and game path):
~/.local/share/lutris/runners/wine/wine-ge-8-26-x86_64
~/Games/SomeGame/drive_c/Program Files/SomeGame/SomeGame.exe

# Heroic (example default install path):
~/Games/Heroic/SomeGame/SomeGame.exe
```

See:
- `integrations/steam/README.md`
- `integrations/lutris/README.md`
- `integrations/heroic/README.md`
</details>

<details>
<summary><strong>[+] 10) Profiles (default / relaxed / pirate-safe)</strong></summary>

Copy one of the presets into your config location:

```bash
cp config/default.toml ~/.config/winewarden/config.toml
# or
cp config/relaxed.toml ~/.config/winewarden/config.toml
# or
cp config/pirate-safe.toml ~/.config/winewarden/config.toml
```
</details>

## Flow Maps (Mini Diagrams)

```
Execution Flow
-------------
winewarden run
   |
   v
[Runner] --> [Monitor] --> [Policy Engine] --> [Reporting]
   |             |                |
   v             v                v
Prefix Manager  Live Watch      Trust Tiers
```

```
Decision Flow
-------------
Access Attempt
   |
   v
Sacred Zone? ---> yes ---> Deny / Redirect / Virtualize
   |
   no
   |
   v
Inside Prefix? ---> no ---> Deny
   |
   yes
   |
   v
Allow + Log
```

## Daemon Mode

```bash
# Start the background daemon
winewarden daemon start

# Run a game through the daemon
winewarden run --daemon /path/to/game.exe -- -arg1 -arg2

# Check daemon health
winewarden daemon ping
```

## Architecture (Separation of Concerns)

- Policy Engine: decisions only
- Monitor: observation without interruption
- Runner: safe command construction
- Prefix Manager: hygiene, snapshots, quarantine
- Reporting: human summaries and JSON
- WineWarden Daemon: background scheduling

```
   [Runner] → [Monitor] → [Policy Engine] → [Reporting]
        ↘        ↘              ↘              ↘
     [Prefix Manager]        [Trust Tiers]   [Human Reports]
```

## Configuration

Configuration is TOML and readable by design. See:

- `config/default.toml`
- `config/relaxed.toml`
- `config/pirate-safe.toml`

Variables supported:

- `${HOME}`
- `${DATA_DIR}`
- `${CONFIG_DIR}`

## Reports (Human First)

Examples of the tone you should expect:

- "This game tried to access files outside its sandbox."
- "That access was denied."
- "Your system remains intact."

## Documentation

- `docs/vision.md`
- `docs/threat-model.md`
- `docs/winewarden-mode.md`
- `docs/trust-tiers.md`
- `docs/sacred-zones.md`
- `docs/prefix-hygiene.md`
- `docs/networking.md`
- `docs/pirate-safe-mode.md`
- `docs/reports.md`
- `docs/configuration.md`
- `docs/architecture.md`
- `docs/glossary.md`

## Status

This is the foundation. Real enforcement hooks are designed to plug into the monitor layer without changing the calm user experience.
