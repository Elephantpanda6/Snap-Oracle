# Snap-Oracle ARM64 Architecture, Future Roadmap & Laptop Ecosystem Guide

## 1. Why Snap-Oracle Exists in the ARM64 Era

Modern personal computing has shifted decisively toward **ARM64 laptops and workstations**: Qualcomm Snapdragon X Elite / X Plus / X2 (Windows on ARM64), NVIDIA N1X / Grace-Blackwell "RTX Spark" 128 GB AI laptops, Apple Silicon M1–M4 (macOS & Asahi Linux), and MediaTek Kompanio Ultrabooks.

Yet security tooling, binary fuzzers, and ABI verification tools still lag behind x86_64:
- **Closed-source Windows on ARM64 DLLs, drivers, printers, and VPN/AV agents** ship compiled `0xAA64` / `0xA641` (ARM64EC) PE32+ binaries without source or DWARF symbols.
- **Local AI runtimes** (`llama.cpp` GGUF loaders, ONNX Runtime, NPU graph compilers) parse untrusted model headers and tensors directly on 64–128 GB unified-memory ARM64 laptops.
- **Subtle cross-arch & microarchitecture bugs** appear exclusively on ARM64:
  - Weak memory ordering (`acquire`/`release` vs x86 TSO).
  - Unaligned SIMD / SVE2 traps or missing `SVE`/`SME` support on Snapdragon X1 (`ARMv8.7-A`).
  - `BTI` landing-pad faults and `PAC` pointer-authentication tag corruption.
  - `16 KB` OS page assumptions failing on Apple Silicon / Asahi Linux vs `4 KB` Windows/Linux.
  - Signed vs unsigned `char` differences (`-fsigned-char` x64 vs unsigned `char` on Linux ARM64).

`snap-oracle` solves this by combining **binary-only static analysis**, **OS-native one-shot coverage traps**, **snapshot state isolation**, and **hardware-aware laptop tuning** in a single dependency-free Zig `0.17.1` toolchain.

---

## 2. Supported ARM64 Laptop & Workstation Matrix

| Profile ID (`--laptop`) | SoC / Microarchitecture | ISA & Security Extensions | Page / Cache | Recommended Tuning | Target Use Cases |
|---|---|---|---|---|---|
| `snapdragon-x-elite` | 12x Qualcomm Oryon Gen 1 | ARMv8.7-A, LSE, PAC, BF16/I8MM (No SVE2/SME) | 4 KB / 64 B | 10 workers, 64 KiB arena, mask `0x0FFF` | Copilot+ Windows DLL fuzzing, ARM64EC verification, enterprise VPN/codec auditing |
| `snapdragon-x-plus` | 8x–10x Qualcomm Oryon Gen 1 | ARMv8.7-A, LSE, PAC | 4 KB / 64 B | 6 workers, 64 KiB arena, mask `0x00FF` | Lightweight on-device Windows ARM64 CI & regression triage |
| `snapdragon-x2-elite` | 12x–18x Oryon Gen 2/3 | ARMv9.2-A, LSE, PAC, BTI, MTE, SVE2, SME | 4 KB / 64 B | 12 workers, 128 KiB arena, `--bti-safe` | High-throughput Windows ARMv9 fuzzing with BTI-protected targets |
| `nvidia-n1x-spark` | 10x Cortex-X925 + 10x A725 + Blackwell UMA | ARMv9.2-A, LSE, PAC, BTI, MTE, SVE2 | 4 KB / 64 B | 10 P-core workers (`0x03FF`), 256 KiB arena | Fuzzing multi-MB GGUF/ONNX AI parsers & CUDA/NPU drivers inside 128 GB UMA |
| `apple-m1-m2` | Firestorm/Avalanche + Icestorm/Blizzard | ARMv8.5-A, LSE, PAC (`arm64e`) | **16 KB** / 128 B | 4 P-core workers, 128 KiB arena | macOS Mach-O `.dylib` & Asahi Linux ELF fuzzing (`16 KB` page safe) |
| `apple-m3-m4` | Apple M3/M4 P+E Cores | ARMv9.2-A, PAC, BTI, **SME** (M4) | **16 KB** / 128 B | 8 P-core workers, 128 KiB arena | Apple Silicon `arm64e` PAC/SME auditing & macOS native snapshot fuzzing |
| `mediatek-kompanio-ultra` | Cortex-X925/X4 + A720/A520 | ARMv9.2-A, PAC, BTI, MTE, SVE2 | 4 KB / 64 B | 4 workers, 64 KiB arena, `--bti-safe` | Linux ARM64 Chromebook / ultrabook native parser auditing |
| `ampere-neoverse-cloud` | Neoverse N1 / N2 / V2 | ARMv8.2–9.0-A, LSE, PAC, BTI, SVE2 | 4 KB / 64 B | 8 workers, 64 KiB arena | GitHub Actions `windows-11-arm`, AWS Graviton, Azure Cobalt CI gates |

---

## 3. High-Value Real-World Use Cases

1. **AI Model Loader Security (`gguf_header_parse` & ONNX/Safetensors Parsers)**:
   - On 128 GB ARM64 AI laptops (NVIDIA N1X / Apple Max / Snapdragon X2), local AI models are untrusted binary files downloaded from the web. `snap-oracle` auto-extracts magic bytes (`"GGUF"`, tensor tags) directly from `MOVZ`/`MOVK` instructions and `.rdata` to fuzz parser bounds before loading weights.
2. **Pre-Flight ISA Compatibility & Hardening Audits (`snap-oracle audit`)**:
   - Before deploying an ARM64 binary fleet-wide across heterogeneous laptops:
     - Detects accidental **SVE/SME instructions** that will crash with `STATUS_ILLEGAL_INSTRUCTION` (`0xC000001D`) on Snapdragon X1 (`ARMv8.7-A`).
     - Detects **4 KB segment alignment** in Linux ELF64 binaries that fail to `mmap` on Apple Silicon **Asahi Linux (`16 KB` pages)**.
     - Verifies **PAC (`paciasp`/`retaa`)** and **BTI (`bti c`)** coverage and counts **LL/SC (`LDXR`/`STXR`)** exclusive-monitor loops vs modern **LSE (`LDADDAL`/`SWP`)** atomics.
3. **Zero-Source Stateful DLL Fuzzing (`ModuleDataSnapshot`)**:
   - Real DLLs keep global counters, caches, and parser state in `.data`/`.bss`. Without snapshot restoration, crashes become non-deterministic. `snap-oracle` restores modified `.data`/`.bss` pages after every run and every minimizer step (`stateful_counter` verifies this in CI).
4. **Cross-Device & Cross-Build Differential Verification (`diff` + `worker`)**:
   - Run two ARM64 optimization builds (`-O2` vs `-O3 -mcpu=oryon-1`), ARM64 vs ARM64EC, or x64 vs ARM64 side-by-side over `diff_protocol` frames to expose ABI, float saturation (`FCVTZS`), or signed-char divergences.

---

## 4. Future Engineering Roadmap

1. **TCP / SSH Remote `diff` Bridge**: Extend `worker` stdio framing with a lightweight TCP listener so an x64 developer workstation can drive live `snap-oracle diff` directly against a Snapdragon X Elite or NVIDIA N1X laptop on the local LAN.
2. **ARM64 Hardware Performance Counters & MTE Tagging**: Expose ARMv9 Memory Tagging Extension (`MTE`) synchronous tag-check fault reporting (`SIGSEGV` `SEGV_MTESERR`) on Snapdragon X2, NVIDIA N1X, and MediaTek ARMv9 Linux kernels for deterministic heap UAF detection without ASan recompilation.
3. **Hyper-V / KVM L2 Micro-VM Fallback**: Wrap targets that spawn child threads or kernel handles inside a lightweight Hyper-V / KVM snapshot loop while keeping L1 in-process speed (`150k–700k exec/s`) for pure parser targets.
4. **ARM64EC Thunk & Guest-Exit Tracer**: Inspects `CHPEMetadataPointer` and `#`-prefixed ARM64EC decorated thunks in `src/imports.zig` alongside `pe.zig` `.a64xrm` detection.

## Enterprise Commercial & DevSecOps Modules (Added in v0.3.0-enterprise-arm64)

| Module | CLI Subcommand | Commercial Enterprise Purpose |
|---|---|---|
| `src/finding.zig` + `src/report.zig` | `report`, `--format sarif\|json\|junit\|gha` | GitHub Code Scanning SARIF 2.1.0, Jenkins JUnit, deterministic FNV-1a finding fingerprints |
| `src/imports.zig` | `deps` | PE/ARM64EC/ELF/Mach-O dependency closure & mixed-arch loadability check (`SO-DEP-001`..`004`) |
| `src/pagesize.zig` | `pagesize` | 4K/16K/64K kernel readiness (`p_align`, ELF mmap congruence, W^X boundary overlap, `0x1000` constants) |
| `src/hardening.zig` | `harden` | PE CFG/ASLR/NX + PAC/BTI prologue ratio; ELF PIE/RELRO/NX/`TEXTREL`/MTE; Mach-O `CS_RUNTIME`/PIE |
| `src/sbom.zig` | `sbom` | CycloneDX 1.5 & SPDX 2.3 JSON SBOM, embedded library fingerprinting, RSDS/Rich/GNU build-id/LC_UUID |
| `src/perfadvisor.zig` | `perf-advise` | Scalar FP back-edge loops, LL/SC vs LSE contention, DotProd/I8MM/BF16 gaps, x64 VEX/EVEX translation |
| `src/portscan.zig` | `portscan` | Comment/literal-safe C/C++/Rust/Zig source & binary porting scanner (`_mm_*`, `__rdtsc`, weak-memory `volatile`, `char`) |
| `src/crash_triage.zig` | `triage` | Defensive CWE root-cause classification (`pac_auth_fail`, `wild_write`, `null_deref`, input taint check) |
| `src/harnessgen.zig` | `gen harness\|repro` | Ready-to-compile C, Zig, Rust (`cargo-fuzz`), and Python reproducers & harnesses |
| `src/cmin.zig` | `cmin` | Exact basic-block weighted set-cover seed distillation + delta-debugging `--tmin` |
| `src/covreport.zig` | `cov` | Binary DrCov v2 (IDA/Ghidra/Binary Ninja Lighthouse), LCOV, JSON diff, self-contained HTML grid |
| `src/symbols.zig` | `sym` | Unified PE `.pdata`/COFF/exports, ELF symtab, Mach-O symbols, Itanium/MSVC demangler, DWARF `.debug_line` |
| `src/bench.zig` | `bench` | Hardware fleet microbenchmarks (`decode`, `cfg`, `mutate`, `snapshot`, `exec`) with median/p95/MAD regression gate |
| `src/crashdb.zig` | `crashdb`, `baseline` | CRC32-verified persistent JSONL database & legacy finding suppression (`--baseline`) |
| `src/ci_gate.zig` | `ci init\|gate` | Native ARM64 CI workflow templates & expiring ISO-date waiver policy enforcement |
| `src/license.zig` | `license` | Offline Ed25519 commercial license verification + authorized-use & non-liability enforcement |
