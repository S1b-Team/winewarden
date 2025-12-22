# Threat Model

## In Scope
- Windows executables attempting to escape Wine/Proton prefixes
- Access to sensitive host paths outside the prefix
- Unwanted access to system sockets or devices
- Prefix degradation over time

## Out of Scope
- Malware removal or signature-based detection
- Kernel-level protection
- Anti-cheat bypass or interference
- Policing software provenance
