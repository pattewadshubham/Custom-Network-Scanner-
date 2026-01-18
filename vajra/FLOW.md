Current project flow (concise, current behaviour)

This file documents the current runtime flow and how components interact. It contains no suggestions or proposed features.

Components

- `cli`: parses arguments and presets, resolves targets and ports, constructs a `ScanJob`, instantiates scanners, and prints results.
- `orchestrator`: accepts a `ScanJob`, schedules worker tasks subject to concurrency and rate limits, aggregates `ProbeResult`s and handles progress reporting.
- `scanner_tcp` / `scanner_syn`: probe targets and return `ProbeResult` objects describing port state, banner (optional), and service match (optional).
- `fingerprint`: consumes banners (if present) and port numbers to produce a `ServiceMatch` that may include `service`, `product`, and `version`.

Runtime flow

1. CLI collects inputs and parameters: `targets`, `ports`, `concurrency`, `rate_limit`, `timeout`, `banner_timeout`, `preset`, `scan_type`.
2. Targets are resolved and port ranges expanded into a list of `Target` items.
3. `ScanJob` is constructed and submitted to `Orchestrator`.
4. `Orchestrator` distributes `Target`s to worker tasks. Each worker calls the selected scanner implementation:
	 - `TcpScanner::scan`:
		 - Attempts a TCP connect with a short initial timeout to detect closed ports quickly.
		 - On timeout or other errors it may retry with the configured full timeout.
		 - If the connection succeeds and the port is in the configured banner-grab list, `BannerGrabber::grab` is invoked.
		 - `BannerGrabber::grab` does a passive read (short) and, if nothing is received, sends a generic active probe (HTTP GET) and attempts one short read. The banner buffer is limited to 512 bytes.
		 - `detect_service(port, banner)` is called; it prefers banner-based heuristics (product/version extraction) and falls back to port-based identification.
		 - A `ProbeResult` is produced with `target`, `state` (Open/Closed/Filtered), optional `banner`, optional `service` and measured `rtt`.
5. `Orchestrator` collects results until all targets are processed, then returns aggregated results to the CLI output layer.

Output

- Results are printed in table/text, JSON or CSV formats. When printing a table, the `SERVICE/VERSION` column is built from `ServiceMatch` fields (`service`, `product`, `version`) when available; otherwise the first line of the captured banner is used; if neither is present `unknown` is printed.

Presets (current semantics)

- `fast`: lower timeouts, no retries, limited banner grabs — favors speed over fingerprint completeness.
- `balanced`: default tuning used by CLI.
- `accurate`: increases timeouts, increases banner timeout and retries (used to get better banner-based detection), the runner sets effective timeout and retries before creating scanners.
- `stealth`: reduces concurrency and enforces lower rate limits.

Notes on fingerprinting behaviour

- Banner-based detection is preferred and may extract product and version when the captured banner contains identifiable strings.
- If no banner is available or parsing yields no product/version, `detect_service_from_port(port)` provides a service name based on common port mappings.

Where to look in the code

- CLI: `crates/cli/src/` (`args.rs`, `runner.rs`, `output.rs`).
- TCP scanner: `crates/scanner_tcp/src/` (`scanner.rs`, `banner.rs`).
- Fingerprint engine: `crates/fingerprint/src/service_detector.rs`.


