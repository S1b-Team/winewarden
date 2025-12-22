# WineWarden

<p align="center">
  <img src="assets/ui/banner.png" alt="WineWarden banner" width="100%" />
</p>

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&pause=1000&color=7CFC00&center=true&vCenter=true&width=820&lines=Play+Windows+games+on+Linux+without+trusting+random+executables+with+your+system." alt="WineWarden tagline" />
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
