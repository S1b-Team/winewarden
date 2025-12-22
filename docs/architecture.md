# Architecture

Boundaries are explicit and auditable.

Layers:
- Policy Engine: decisions only
- Runner: process construction and environment sanitation
- Monitor: observation without interruption
- Prefix Manager: hygiene, snapshots, quarantine
- Reporting: human summaries and JSON
- WineWarden Daemon: background scheduling
