# Vajra Scanner — Complete Commands Reference

This document replaces the previous `COMMANDS.md` and provides a compact, thorough reference for building and using Vajra locally. It focuses on safe, repeatable examples and maps Vajra flags to common Nmap equivalents where relevant.

Important: Do not run scans against systems you do not own or do not have explicit permission to scan.

## Build & validate

- Build debug (fast):

```bash
cargo build
```

- Build optimized release (recommended for performance):

```bash
cargo build --release
```

- Run unit tests (no network):

```bash
cargo test
```

- Build a single crate (faster during development):

```bash
cargo build -p vajra_scanner_tcp
```

## CLI overview

Command pattern (binary must be built first):

```bash
./target/release/vajra scan [OPTIONS]
```

Key options:
- `-t, --targets <targets>` — Comma-separated list: IPs, hostnames, CIDRs, or ranges.
- `-p, --ports <ports>` — Comma-separated ports or ranges (e.g. `22,80,443` or `1-1024`).
- `--scan-type <tcp|syn>` — SYN requires root.
- `-c, --concurrency <n>` — Worker pool size.
- `-r, --rate <pps>` — Rate limit (packets per second).
- `--timeout <ms>` — Probe timeout in ms.
- `--banner-timeout <ms>` — Timeout for banner grabs.
- `--preset <fast|balanced|accurate|stealth>` — Tuned defaults.
- `--format <text|json|csv>` — Output format.

## Examples (safe, permissioned)

### Basic scans
```bash
# Single host
./target/release/vajra scan -t scanme.nmap.org -p 22,80,443

# Multiple hosts
./target/release/vajra scan -t 8.8.8.8,1.1.1.1 -p 53,80,443

# Hostname that resolves to many IPs
./target/release/vajra scan -t google.com -p 80,443
```

### Ranges & CIDR
```bash
# Range
./target/release/vajra scan -t 192.168.1.1-192.168.1.50 -p 22,80

# CIDR (subject to safety cap)
./target/release/vajra scan -t 10.0.0.0/24 -p 1-1024
```

### Presets
```bash
# Fast (less accurate, faster)
./target/release/vajra scan -t example.com -p 1-1024 --preset fast

# Balanced
./target/release/vajra scan -t example.com -p 1-1024 --preset balanced

# Accurate (more banner grabs, higher timeouts)
./target/release/vajra scan -t example.com -p 22,80,443 --preset accurate --timeout 5000 --banner-timeout 1500

# Stealth (low rate)
./target/release/vajra scan -t example.com -p 1-1024 --preset stealth -r 50 -c 10
```

### Output formats
```bash
# Table (default)
./target/release/vajra scan -t example.com -p 22,80,443

# JSON
./target/release/vajra scan -t example.com -p 22,80,443 --output-format json > results.json

# CSV
./target/release/vajra scan -t example.com -p 22,80,443 --output-format csv > results.csv
```

### SYN scan (requires root)
```bash
sudo ./target/release/vajra scan -t 192.168.1.0/24 -p 1-1024 --scan-type syn -c 500
```

## Safety & etiquette
- Only scan hosts you own or have explicit permission to scan.
- Start small before scaling to ranges.
- Use `--preset stealth` or reduce `-c`/`-r` for target networks you do not control.

## Troubleshooting
- If builds fail due to native libs (openssl, sqlite), install system dev packages (Debian/Ubuntu example):

```bash
sudo apt-get update
sudo apt-get install build-essential pkg-config libssl-dev libsqlite3-dev
```

- If banner/version info is missing on HTTPS ports, increase `--banner-timeout`.

## Nmap mapping
- Vajra `--preset accurate` ≈ Nmap `-sV`.
- Vajra TCP connect scan ≈ Nmap `-sT`.
- Vajra SYN scan ≈ Nmap `-sS` (requires root).

## Automation example
```bash
# Save JSON and check for open ports
./target/release/vajra scan -t scanme.nmap.org -p 1-1024 --format json > out.json
jq '.[] | select(.state == "Open")' out.json | wc -l
```

## Vajra ↔ Nmap command matrix (quick reference)

The table below lists common scan tasks and shows a recommended Vajra command and the closest Nmap equivalent. Use these as a quick copy/paste matrix.

1) Single host, common service ports
- Vajra:
	```bash
	./target/release/vajra scan -t example.com -p 22,80,443
	```
- Nmap equivalent:
	```bash
	nmap -sT -p22,80,443 -Pn example.com -T4
	```

2) Full TCP connect scan of well-known ports (1-1024)
- Vajra:
	```bash
	./target/release/vajra scan -t example.com -p 1-1024 --preset balanced
	```
- Nmap equivalent:
	```bash
	nmap -sT -p1-1024 -Pn example.com -T4
	```

3) Fast high-rate scan (be careful)
- Vajra:
	```bash
	./target/release/vajra scan -t example.com -p 1-1024 --preset fast -c 1000 -r 5000
	```
- Nmap equivalent:
	```bash
	nmap -sT -p1-1024 -Pn example.com -T5 --min-rate 5000
	```

4) Accurate service/version detection (active probes)
- Vajra:
	```bash
	./target/release/vajra scan -t example.com -p 22,80,443 --preset accurate --timeout 5000 --banner-timeout 1500
	```
- Nmap equivalent:
	```bash
	nmap -sT -sV -p22,80,443 -Pn example.com -T3
	```

5) SYN (stealth) scan across a range (requires root)
- Vajra:
	```bash
	sudo ./target/release/vajra scan -t 10.0.0.0/24 -p 1-1024 --scan-type syn -c 500
	```
- Nmap equivalent:
	```bash
	sudo nmap -sS -p1-1024 -Pn 10.0.0.0/24 -T4
	```

6) Scan multiple targets (comma-separated)
- Vajra:
	```bash
	./target/release/vajra scan -t 8.8.8.8,1.1.1.1,example.com -p 80,443
	```
- Nmap equivalent:
	```bash
	nmap -sT -p80,443 -Pn 8.8.8.8 1.1.1.1 example.com
	```

7) CIDR scan (small to medium networks)
- Vajra:
	```bash
	./target/release/vajra scan -t 10.0.0.0/24 -p 1-1024
	```
- Nmap equivalent:
	```bash
	nmap -sT -p1-1024 -Pn 10.0.0.0/24 -T4
	```

8) Range scan (start-end)
- Vajra:
	```bash
	./target/release/vajra scan -t 192.168.1.10-192.168.1.50 -p 22,80
	```
- Nmap equivalent:
	```bash
	nmap -sT -p22,80 -Pn 192.168.1.10-192.168.1.50 -T4
	```

9) Service-specific quick check (HTTP on common ports)
- Vajra:
	```bash
	./target/release/vajra scan -t example.com -p 80,443,8080,8443 --preset accurate
	```
- Nmap equivalent:
	```bash
	nmap -sT -sV -p80,443,8080,8443 -Pn example.com -T3
	```

10) Mail service focus (SMTP/POP/IMAP)
- Vajra:
	```bash
	./target/release/vajra scan -t mail.example.com -p 25,110,143,465,587,993,995 --preset accurate
	```
- Nmap equivalent:
	```bash
	nmap -sT -sV -p25,110,143,465,587,993,995 -Pn mail.example.com -T3
	```

11) Database service ports
- Vajra:
	```bash
	./target/release/vajra scan -t db-host -p 3306,5432,27017,6379,9200 --preset accurate
	```
- Nmap equivalent:
	```bash
	nmap -sT -sV -p3306,5432,27017,6379,9200 -Pn db-host -T3
	```

12) Performance tuning examples
- Balanced (recommended):
	```bash
	./target/release/vajra scan -t example.com -p 1-1024 --preset balanced -c 500 -r 1000
	```
- Conservative:
	```bash
	./target/release/vajra scan -t example.com -p 1-1024 --preset stealth -c 200 -r 200
	```

13) Extract banners only (lower noise)
- Vajra (only common ports; adjust list):
	```bash
	./target/release/vajra scan -t example.com -p 21,22,25,80,110,443 --preset accurate --banner-timeout 3000
	```
- Nmap (service/version):
	```bash
	nmap -sT -sV -p21,22,25,80,110,443 -Pn example.com -T3
	```

14) Save results for diffing/automation
- Vajra JSON:
	```bash
	./target/release/vajra scan -t example.com -p 1-1024 --output-format json > vajra.json
	```
- Nmap JSON:
	```bash
	nmap -sT -sV -p1-1024 -Pn example.com -T3 -oJ nmap.json
	```

15) Run a quick remote-only check of a single port (table output)
- Vajra:
	```bash
	./target/release/vajra scan -t 23.220.75.245 -p 21,22,23 --preset balanced --timeout 5000 --banner-timeout 2000
	```
- Nmap:
	```bash
	nmap -sT -sV -p21,22,23 -Pn 23.220.75.245 -T3
	```

Notes & tips
- Replace `example.com` with the actual target or IPs. Use `--format json` for machine-readable output.
- For SYN scans, prefer `-sS` with sudo. For connect scans, `-sT` or Vajra default is appropriate.
- Use `--preset accurate` when you want the scanner to invest more time in banner grabs and version detection.

```



