# Vajra Core Makefile
# Rust workspace build automation

# Variables
CARGO = cargo
TARGET_DIR = target
RELEASE_DIR = $(TARGET_DIR)/release
DEBUG_DIR = $(TARGET_DIR)/debug
BINARY_NAME = vajra
ARCHIVE_NAME = 24112035.tar.gz

# Default target
.PHONY: all
all: build

# Build targets
.PHONY: build
build:
	$(CARGO) build

.PHONY: release
release:
	$(CARGO) build --release

.PHONY: debug
debug:
	$(CARGO) build

# Test targets
.PHONY: test
test:
	$(CARGO) test

.PHONY: test-release
test-release:
	$(CARGO) test --release

# Run targets
.PHONY: run
run:
	$(CARGO) run --bin $(BINARY_NAME)

.PHONY: run-release
run-release:
	$(CARGO) run --release --bin $(BINARY_NAME)

# Example targets
.PHONY: example-simple
example-simple:
	$(CARGO) run --example simple_scan

.PHONY: example-concurrent
example-concurrent:
	$(CARGO) run --example concurrent_scan

.PHONY: examples
examples: example-simple example-concurrent

# Development targets
.PHONY: check
check:
	$(CARGO) check

.PHONY: clippy
clippy:
	$(CARGO) clippy -- -D warnings

.PHONY: fmt
fmt:
	$(CARGO) fmt

.PHONY: fmt-check
fmt-check:
	$(CARGO) fmt -- --check

# Clean targets
.PHONY: clean
clean:
	$(CARGO) clean
	rm -f $(ARCHIVE_NAME)

.PHONY: clean-all
clean-all: clean
	rm -rf $(TARGET_DIR)

# Package target for submission
.PHONY: package
package: clean
	@echo "Creating submission archive: $(ARCHIVE_NAME)"
	tar --exclude='$(TARGET_DIR)' \
	    --exclude='.git' \
	    --exclude='*.tar.gz' \
	    --exclude='.github' \
	    --exclude='Cargo.lock' \
	    -czf $(ARCHIVE_NAME) \
	    crates/ \
	    examples/ \
	    Cargo.toml \
	    Makefile \
	    README.md \
	    COMMANDS.md \
	    FLOW.md
	@echo "Archive created: $(ARCHIVE_NAME)"
	@ls -lh $(ARCHIVE_NAME)

# Install target
.PHONY: install
install: release
	$(CARGO) install --path crates/cli

# Documentation
.PHONY: doc
doc:
	$(CARGO) doc --no-deps --open

# Benchmark (if any benchmarks exist)
.PHONY: bench
bench:
	$(CARGO) bench

# Help target
.PHONY: help
help:
	@echo "Vajra Core Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  build          - Build debug version"
	@echo "  release        - Build release version"
	@echo "  test           - Run tests"
	@echo "  run            - Run debug binary"
	@echo "  run-release    - Run release binary"
	@echo "  examples       - Run all examples"
	@echo "  check          - Check code without building"
	@echo "  clippy         - Run clippy linter"
	@echo "  fmt            - Format code"
	@echo "  clean          - Clean build artifacts"
	@echo "  package        - Create submission archive"
	@echo "  install        - Install binary to system"
	@echo "  doc            - Generate documentation"
	@echo "  help           - Show this help"

# Sample input cases (add your specific test cases here)
.PHONY: sample-inputs
sample-inputs:
	@echo "Running sample input cases..."
	@echo "Example 1: Simple scan"
	$(CARGO) run --example simple_scan
	@echo "Example 2: Concurrent scan"
	$(CARGO) run --example concurrent_scan