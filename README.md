# Snap-Oracle

**ARM64-First Cross-OS Binary Snapshot Fuzzer, AArch64 ISA Auditor & Differential Verification Engine** (written in Zig `0.17.1`).

`snap-oracle` targets the ARM64 ecosystem natively across **Windows on ARM64 (`0xAA64` / `ARM64EC`)**, **Linux AArch64 (`ELF64`)**, and **Apple Silicon macOS (`Mach-O arm64` / `arm64e`)**, with host x64 compatibility for cross-auditing and local development.

Instead of restarting processes or needing source code, `snap-oracle` parses PE32+ / ELF64 / Mach-O binaries, builds a recursive-descent basic-block CFG, arms one-shot traps (`brk #0xF000` on Windows ARM64, `brk #0` on Linux/macOS ARM64, `int3` on x64), resets both input arena pages (`MEM_WRITE_WATCH` / page scan) and writable DLL/DSO data sections (`.data`/`.bss`), and feeds an ARM64 immediate-aware dictionary mutator.

## Key ARM64-First Capabilities

- **True Cross-OS ARM64 Native Support**:
  - **Windows on ARM64** (`aarch64-windows-gnu`): PE32+ `0xAA64` / `ARM64EC`, 8-byte `.pdata` + `.xdata`, `brk #0xF000` (`0xD43E0000`), `_ARM64_NT_CONTEXT::Pc` rewind, `FlushInstructionCache` (safe under Hyper-V VMs), and `MEM_WRITE_WATCH` dirty-page reset.
  - **Linux ARM64** (`aarch64-linux-gnu`): ELF64 `EM_AARCH64` (`183`), `GNU_PROPERTY_AARCH64_FEATURE_1_AND` (`BTI`/`PAC`), `SA_SIGINFO` signal recovery, `brk #0` (`0xD4200000`), `dc cvau` / `ic ivau` coherency, and 4 KB / 16 KB page support.
  - **Apple Silicon macOS** (`aarch64-macos`): Mach-O 64-bit `arm64`/`arm64e`, `LC_FUNCTION_STARTS` ULEB128 decoding, 16 KB page alignment awareness, and `sys_icache_invalidate`.
- **Recursive-Descent AArch64 CFG & Hazard Avoidance (`src/arm64_isa.zig`, `src/cfg.zig`)**:
  - Follows real control flow (`B`, `BL`, `B.cond`, `CBZ`, `CBNZ`, `TBZ`, `TBNZ`, `RET`, `RETAA`, `RETAB`, `BR`, `BRAA`, `HLT`, `UDF`) so literal pools are never misdecoded as code.
  - Detects `LDXR`..`STXR` exclusive monitor critical sections so one-shot traps never trigger livelock inside LL/SC atomics.
  - Supports `--bti-safe` mode to step over `BTI` landing pads and `PACIASP`/`PACIBSP` prologues before arming traps.
- **ARM64 Immediate & `.rdata` Dictionary Extraction (`src/dict_extract.zig`)**:
  - Automatically reconstructs 16/32/64-bit magic constants directly from AArch64 `MOVZ`/`MOVK` chains and `CMP` immediates alongside `.rdata`/`.rodata` strings.
- **ARM64 Laptop Hardware Profiles & Readiness Auditor (`src/arm_laptops.zig`, `src/audit.zig`)**:
  - Live `hwinfo` probe and built-in tuning profiles for **Qualcomm Snapdragon X Elite / X Plus / X2**, **NVIDIA N1X / RTX Spark 128 GB**, **Apple Silicon M1–M4**, **MediaTek Kompanio**, and **Ampere/Graviton CI**.
  - `audit <binary>` reports PAC/BTI/LSE/RCPC/NEON/SVE/SME/LDXR instruction telemetry, cross-laptop compatibility, and top fuzzable exports.
- **Deterministic `.data`/`.bss` Reset + Multi-Worker Scaling (`src/dll_snapshot.zig`, `src/pool.zig`, `src/worker.zig`)**:
  - Restores dirty writable target data pages after every run and minimization step, supports `--jobs N` multi-process corpus syncing, and provides framed `diff_protocol` stdio workers.

## Build

Requires Zig `0.17.1`:

```powershell
# Run full unit & integration test suite
zig build test --summary all

# Build natively for host
zig build -Doptimize=ReleaseFast

# Cross-compile for all ARM64 platforms
zig build -Dtarget=aarch64-windows-gnu -Doptimize=ReleaseFast
zig build -Dtarget=aarch64-linux-gnu -Doptimize=ReleaseFast
zig build -Dtarget=aarch64-macos -Doptimize=ReleaseFast
```

## Usage

```powershell
# Probe live host ARM64 silicon / page-size / matched laptop profile
.\zig-out\bin\snap-oracle.exe hwinfo

# List all supported ARM64 laptop & workstation profiles
.\zig-out\bin\snap-oracle.exe profiles

# Audit any ARM64 PE32+ / ELF64 / Mach-O binary for PAC/BTI/LSE/SVE/SME & laptop compatibility
.\zig-out\bin\snap-oracle.exe audit .\zig-out\bin\test_target.dll

# Inspect binary headers, functions, and recursive-descent basic blocks
.\zig-out\bin\snap-oracle.exe inspect .\zig-out\bin\test_target.dll

# Coverage-guided snapshot fuzzing with ARM64 dictionary extraction & .data reset
mkdir corp
.\zig-out\bin\snap-oracle.exe fuzz --target .\zig-out\bin\test_target.dll --entry parse_packet --iters 1000000 --corpus corp --bti-safe

# Fuzz stateful .data target (`stateful_counter`) or GGUF AI parser (`gguf_header_parse`)
.\zig-out\bin\snap-oracle.exe fuzz --target .\zig-out\bin\test_target.dll --entry stateful_counter --iters 50000
.\zig-out\bin\snap-oracle.exe fuzz --target .\zig-out\bin\test_target.dll --entry gguf_header_parse --iters 200000

# Multi-worker pool pinned to an ARM64 laptop profile
.\zig-out\bin\snap-oracle.exe fuzz --target .\zig-out\bin\test_target.dll --entry parse_packet --iters 2000000 --corpus corp --jobs 4 --laptop snapdragon-x-elite

# Replay & minimize a crash with full .data + arena snapshot isolation
.\zig-out\bin\snap-oracle.exe replay --target .\zig-out\bin\test_target.dll --entry stateful_counter --input crash_xxx.bin --minimize

# Differential execution across two binaries (or via `worker` over stdio/SSH)
.\zig-out\bin\snap-oracle.exe diff --a build_a.dll --b build_b.dll --entry arm64_abi_probe --iters 10000
```

See [docs/ARM64_ARCHITECTURE_AND_LAPTOPS.md](docs/ARM64_ARCHITECTURE_AND_LAPTOPS.md) for the full ARM64 roadmap, use cases, and laptop hardware compatibility guide.

## License

**Non-Commercial & Authorized-Use License (Paid Commercial License Required for Companies)** — see [LICENSE](LICENSE).

- **Individuals & Non-Commercial Users**: Free for personal, educational, academic, and non-commercial research use on systems/binaries you own or have explicit permission to test.
- **Companies & Commercial Use**: Strictly prohibited without a **paid Commercial License** from the copyright holder (`Elephantpanda6`).
- **Author Protection & Disclaimer**: Provided "AS IS" strictly for lawful, authorized testing; the author (`Elephantpanda6`) bears no responsibility or liability for any activities performed by users, who assume sole legal responsibility and agree to indemnify the author.
