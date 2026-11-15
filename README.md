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

Add `--corpus <dir>` to make the run coverage-guided. Files in the directory (up to 64 KB each) seed the queue, and any input that reaches a new basic block is added to the queue and written back to the same directory as `seed_<hash>.bin`. The directory has to exist already. Without `--corpus` the run still tracks coverage, it just starts from a single 16-byte seed and keeps the queue in memory.

```powershell
mkdir corp
.\zig-out\bin\snap-oracle.exe fuzz --target .\zig-out\bin\test_target.dll --entry parse_packet --iters 5000000 --corpus corp
```

The final line reports `exec_per_sec`, `edges=<hit>/<armed>`, `corpus`, `crashes (unique)` and `dirty_pages_reset`.

Run two builds side by side to flag return/crash divergences:

```powershell
.\zig-out\bin\snap-oracle.exe diff --x64 a.dll --arm64 b.dll --entry fuzz_entry --iters 1000
```

Replay a single input file and inspect return value or caught exception (`code` / `addr`):

```powershell
.\zig-out\bin\snap-oracle.exe replay --target .\zig-out\bin\test_target.dll --entry fuzz_entry --input crash.bin
```

With `--minimize`, a crashing input is shrunk and the result is written next to it as `<input>.min`. The reducer first drops large chunks (halves, then quarters, down to 2 bytes), then removes single bytes until a full pass changes nothing, and only keeps a candidate if it still crashes with the same exception code.

```powershell
.\zig-out\bin\snap-oracle.exe replay --target .\zig-out\bin\test_target.dll --entry fuzz_entry --input crash.bin --minimize
```

Inputs to a target that validates its own length fields (like `parse_packet`) usually won't shrink, because removing a byte breaks the length check before the crash is reached.

## How coverage feedback works

The target has no instrumentation, so coverage comes from the binary itself. Before the first iteration `snap-oracle` reads the DLL from disk and walks every `.pdata` function inside `.text`. On x64 it uses a small instruction-length decoder and follows direct branches from each function entry, so every block address it finds is a real instruction boundary and inline data or jump tables are never decoded. Branch targets and the instruction after each conditional branch become block entries. On ARM64 the fixed-width instructions are scanned directly.

Each block start is patched with a one-shot trap, `0xCC` (`INT3`) on x64 or `BRK #0` on ARM64, after the original bytes are saved (`VirtualProtect` to RWX, write, restore the old protection, flush the instruction cache). When execution reaches a block the Vectored Exception Handler sees the breakpoint, puts the original instruction back, rewinds `Rip` to the trapped address (x64 reports the address after the `INT3`), records the edge in `CoverageBitmap` and returns `EXCEPTION_CONTINUE_EXECUTION`. Each block traps once, so after the first hit it costs nothing. If an input hits a block for the first time it goes into the corpus. Unhit traps are restored when the run ends, before the DLL is unloaded.

## The parse_packet target

`test_target.dll` exports `fuzz_entry` (a tiny `BOOM` check plus a hash) and `parse_packet`, a layered packet parser: `S` `N` magic, a version byte of 1 to 3, a type byte, a length byte that must match the payload, then a type dispatch into a TLV list, a checksum record, or a nested record. The nested path needs version 2 or higher, a `Q` marker, a flags byte with the top bit set, an inner length that matches exactly and a body starting `DE AD`, and that is where it faults. Blind mutation almost never gets that far, but with the corpus enabled a few million iterations are enough to find it. A 10-byte example that crashes it:

```
53 4E 02 03 05 51 80 02 DE AD
```

On this machine `test_target.dll` runs at roughly 450k to 700k executions per second natively with coverage tracking on, depending on how many new blocks each run finds. That figure comes from the `parse_packet` entry, one thread, on x64.

## Notes

- Tested natively on Windows x64; ARM64 builds compile via `aarch64-windows-gnu` and include `cntvct_el0` + cache invalidation (`dc cvau` / `ic ivau`), though live `diff` across architectures requires running on an ARM64 host or external emulator for the ARM64 binary.
- Crashes are deduplicated by fault code/address and saved as `crash_<hash>.bin`.
- Coverage is block coverage at function granularity of the `.pdata` table; code that is only reachable through jump tables or indirect calls is not armed.

## License

MIT — see [LICENSE](LICENSE).
