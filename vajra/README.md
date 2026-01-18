# Vajra Core

Monorepo workspace for Vajra core engine (Rust).

Structure:
- crates/common: shared types & traits
- crates/scanner_tcp: TCP connect scanner
- crates/orchestrator: job manager & scheduler
- crates/cli: CLI front-end
- crates/target_resolver: CIDR/DNS resolver (stub)
- crates/scanner_syn: raw SYN scanner (stub)
- crates/fingerprint: service detection (stub)
- crates/plugin_host: WASM plugin host (stub)
- crates/storage: persistence (stub)
- crates/telemetry: metrics (stub)

See `examples/` for basic usages.
