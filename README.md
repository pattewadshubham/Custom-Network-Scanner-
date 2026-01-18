# Custom Network Scanner

A comprehensive network security analysis toolkit featuring the Vajra network scanner and malware analysis capabilities.

## 🚀 Features

- **Vajra Network Scanner**: High-performance Rust-based network scanner
- **Malware Analysis**: Dynamic and static analysis tools
- **Security Assessment**: Port scanning, service detection, vulnerability assessment

## 📁 Project Structure

```
├── vajra/                 # Rust network scanner
│   ├── crates/           # Modular scanner components
│   ├── examples/         # Usage examples
│   └── target/           # Build artifacts
├── code_analysis/        # Static analysis tools
├── Malware/             # Malware analysis reports
└── Flare-vm/            # VM analysis environment
```

## 🛠️ Vajra Scanner

**Components:**
- TCP Connect Scanner
- SYN Scanner (raw sockets)
- Service Fingerprinting
- Target Resolution
- Job Orchestration

**Quick Start:**
```bash
cd vajra
cargo build --release
cargo run --example simple_scan
```

## 📊 Analysis Capabilities

- Port scanning and enumeration
- Service version detection
- Network topology mapping
- Security vulnerability assessment
- Malware behavior analysis

## 🔧 Requirements

- Rust 1.70+
- Linux/Unix environment
- Root privileges (for SYN scanning)

## 📝 Usage

See `vajra/COMMANDS.md` for detailed usage instructions and examples.

## 🎯 Use Cases

- Network security auditing
- Penetration testing
- Infrastructure assessment
- Malware analysis
- Security research

---
**Author**: Shubham Pattewad  
**Project**: Custom Network Scanner & Security Analysis Toolkit
