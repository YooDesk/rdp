
## 2026-11-12 final Android/device migration acceptance

Migrated upstream `c0975f27b05dc33dd303742cea519f390552fb4c` with the standalone repository boundaries preserved.
- build-android.yml: success; release `android-v0.1.0-ci.1`; run https://github.com/YooDesk/rdp/actions/runs/43201349881; tested commit `f07bd73d32beb1ef745f387869972c21a9d83b6b`.
- build.yml: success; release `v0.1.0-ci.45`; run https://github.com/YooDesk/rdp/actions/runs/43201988069; tested commit `f07bd73d32beb1ef745f387869972c21a9d83b6b`.
Android builds use ARM64, API 24 and NDK 26.1.10909125 with 16 KiB ELF load alignment. Actual Android-device acceptance remains pending.
Original repository visibility and workflow activation were restored after the build. Documentation-only acceptance commits do not change the tested executable source.


## 2026-11-21 MIPS plugin startup correction

WebService dynamic-plugin acceptance exposed startup failure in released MIPS plugins. Vendor the exact libc 0.2.191 archive with Connector's reviewed five MIPS64 architecture-selector corrections (socket options/types, signals, sigaction and pthread mutex ABI). Keep upstream licenses and PATCHES provenance. Remove the old MIPS socket-test exclusions. Add an exported-C-ABI startup regression that binds the actual plugin loopback listener, verifies missing transport token returns HTTP 403, stops the runtime and checks the listener is released. Full platform builds and WebService dynamic integration remain required before replacing released dependencies.

2026-11-25 shared transport sync: bounded browser receive windows and current API descriptions synchronized; bundled shared SFTP source aligned. RDP already has independent direction pumps, so its business relay is unchanged. Host dynamic-plugin regression passed with the existing RDP DLL. No release.

QEMU release acceptance (2026-11-25, explicit user decision): cross-compile, inspect target ABI/static or shared-library dependencies, and perform bounded startup/config/plugin-load smoke checks. Do not run full Rust/Go test suites or throughput gates under emulation. Existing native-runner regression policy is unchanged. Full-suite results and physical throughput must be established on native hardware.
