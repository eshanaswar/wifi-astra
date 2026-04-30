BINARY     := bin/wifi-astra
BUILD_PKG  := ./cmd/astra/
MODULES_DIR := modules

.PHONY: all build install clean test lint check

all: build

## build: compile the wifi-astra binary into bin/
build:
	@mkdir -p bin
	go build -o $(BINARY) $(BUILD_PKG)
	@echo "[✓] Built $(BINARY)"

## install: build and copy binary to /usr/local/bin (requires root)
install: build
	@if [ "$$(id -u)" -ne 0 ]; then echo "[✗] install requires root (sudo make install)"; exit 1; fi
	install -m 755 $(BINARY) /usr/local/bin/wifi-astra
	@echo "[✓] Installed to /usr/local/bin/wifi-astra"

## uninstall: remove binary from /usr/local/bin (requires root)
uninstall:
	@if [ "$$(id -u)" -ne 0 ]; then echo "[✗] uninstall requires root (sudo make uninstall)"; exit 1; fi
	rm -f /usr/local/bin/wifi-astra
	@echo "[✓] Removed /usr/local/bin/wifi-astra"

## test: run the full Go test suite
test:
	go test ./...

## lint: shellcheck all module scripts
lint:
	shellcheck -S warning $(MODULES_DIR)/*.sh
	@echo "[✓] All module scripts pass shellcheck"

## check: build check + test + lint (run before committing)
check:
	go build -o /dev/null $(BUILD_PKG)
	go test ./...
	shellcheck -S warning $(MODULES_DIR)/*.sh
	@echo "[✓] All checks passed"

## clean: remove build artifacts
clean:
	rm -f $(BINARY)

help:
	@grep -E '^## ' Makefile | sed 's/## /  /'
