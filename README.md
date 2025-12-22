# WineWarden

"Play Windows games on Linux without trusting random executables with your system."

WineWarden is a calm, always-on protection layer for Wine, Proton, Lutris, and Steam. It is not an antivirus. It does not moralize. It exists so you can play without anxiety.

## What It Does

- WineWarden Mode: silent protection with no prompts during gameplay
- Trust Tiers: clear reassurance signals (Green, Yellow, Red)
- Sacred Zones: protect the places games should never need
- Prefix Hygiene: keep prefixes clean and stable over time
- Network Safety: observe without breaking multiplayer
- Pirate-Safe Mode: stronger isolation with zero judgment
- Human Reports: short, calm summaries after each run

## Architecture (Separation of Concerns)

- Policy Engine: evaluates access attempts and trust tiers
- Execution Monitor: runs the game and collects events
- Prefix Manager: hygiene scanning and lightweight snapshots
- Reporting Layer: human summaries and structured output

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

## Calm Defaults

- Secure by default
- Easy to relax
- Hard to break accidentally

## CLI Overview

- `winewarden init` write the default config
- `winewarden run` run a game with WineWarden Mode
- `winewarden report` render a human summary
- `winewarden trust get/set` manage trust tiers
- `winewarden prefix scan/snapshot` hygiene and snapshots

## Configuration

See `config/default.toml` for the default policy. The file is human-readable TOML and uses variables:

- `${HOME}`
- `${DATA_DIR}`
- `${CONFIG_DIR}`

## Status

This is the foundation. Real enforcement hooks are designed to plug into the monitor layer without changing the calm user experience.
