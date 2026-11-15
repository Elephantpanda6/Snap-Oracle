# Snap-Oracle

In-process snapshot fuzzer and differential runner for Windows PE32+ binaries (`x64` / `ARM64`), written in Zig with inline assembly.

Instead of restarting a target process on every input or needing source code, `snap-oracle` loads a compiled `.dll`, parses `.pdata` / exports, catches faults with a Vectored Exception Handler (`RtlCaptureContext` / `RtlRestoreContext`), and resets only dirtied 4 KB pages using Windows `MEM_WRITE_WATCH` (`GetWriteWatch` with `WRITE_WATCH_FLAG_RESET`).

## Build

Needs Zig 0.17.1 or newer on Windows:

```powershell
zig build test --summary all
zig build -Doptimize=ReleaseFast
```

Cross-compiling for Windows ARM64:

```powershell
zig build -Dtarget=aarch64-windows-gnu -Doptimize=ReleaseFast
```

This builds `snap-oracle.exe` and a small `test_target.dll` in `zig-out\bin\`.

## Usage

Inspect PE32+ headers, `.pdata` functions, exports, and decoded basic blocks:

```powershell
.\zig-out\bin\snap-oracle.exe inspect .\zig-out\bin\test_target.dll
```

Fuzz an exported function (`fn([*]const u8, usize) callconv(.c) u64`) inside a `MEM_WRITE_WATCH` arena:

```powershell
.\zig-out\bin\snap-oracle.exe fuzz --target .\zig-out\bin\test_target.dll --entry fuzz_entry --iters 50000
```

Run two builds side by side to flag return/crash divergences:

```powershell
.\zig-out\bin\snap-oracle.exe diff --x64 a.dll --arm64 b.dll --entry fuzz_entry --iters 1000
```

Replay a single input file and inspect return value or caught exception (`code` / `addr`):

```powershell
.\zig-out\bin\snap-oracle.exe replay --target .\zig-out\bin\test_target.dll --entry fuzz_entry --input crash.bin
```

## Notes

- Tested natively on Windows x64; ARM64 builds compile via `aarch64-windows-gnu` and include `cntvct_el0` + cache invalidation (`dc cvau` / `ic ivau`), though live `diff` across architectures requires running on an ARM64 host or external emulator for the ARM64 binary.
- Crashes are deduplicated by fault code/address and saved as `crash_<hash>.bin`.

## License

MIT — see [LICENSE](LICENSE).
