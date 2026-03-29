# memscan Test Report

**Date:** 2026-03-28  
**Tester:** ENI (subagent)  
**Environment:** Linux 6.12.74+deb13+1-amd64, Python 3, x86_64

---

## Test Results Summary

- **Total tests run:** 28
- **Passed:** 24
- **Failed (before fixes):** 4
- **Errors fixed:** 4

---

## What Works

### Process Listing
- ✅ `memscan list` — Lists all processes with PID, arch, name
- ✅ `memscan list --name python` — Filters by process name
- ✅ `memscan list --name bash` — Returns multiple bash processes
- ✅ `memscan list --name nonexistent` — Returns 0 results gracefully
- ✅ `memscan list --json` — Valid JSON output
- ✅ `memscan list --csv` — Valid CSV output
- ✅ `memscan list --raw` — Pipe-friendly raw output

### Value Scanning
- ✅ `--value 0 --type int32 --scan-type exact` — Found 641,533 zero values
- ✅ `--value 100 --type int32 --scan-type greater` — Found 183,137 results
- ✅ `--value 100 --type int32 --scan-type less` — Found 668,771 results
- ✅ `--value 50 --value2 150 --type int32 --scan-type between` — Found 4,247 results
- ✅ `--value 0x7f454c46 --type int32` — Hex value parsing works
- ✅ `--value 3.14 --type float` — Float parsing works
- ✅ `--value "bash" --type string` — Found 24 string matches (after fix)
- ✅ `--type int64 --scan-type exact` — 64-bit scanning works

### AOB Pattern Scanning
- ✅ `--pattern "7f 45 4c 46"` — Found 9 ELF header matches
- ✅ Wildcard patterns with `??` syntax supported

### Memory Write
- ✅ `--address 0x... --write 9999` — Successfully wrote int32 value
- ✅ Write via `/proc/pid/mem` works with root

### Watch/Monitor
- ✅ `--watch 0x... --interval 500` — Initial read works, monitoring starts
- ✅ Change detection and logging functional

### Save/Load
- ✅ `--save` — Saves results to file in human-readable format
- ✅ `--load` — Parses saved file back into results for refinement
- ✅ `--refine --load` — Refinement from loaded results works

### Pointer Scanning
- ✅ `--ptr-scan --start ... --end ...` — Generates pointer map
- ✅ Returns "No pointers found" gracefully when empty

### Injection
- ✅ `--inject /dev/null` — Handles empty shellcode file
- ✅ `--luax "print('test')"` — Framework loads, reports Lua state not found (expected)

### Output Formats
- ✅ `--raw` — Clean pipe-friendly output
- ✅ `--human` — Default readable format with box drawing

### Safe Mode
- ✅ `--safe` flag blocks writes with clear warning message
- ✅ `--safe` still allows scanning and reading

### Edge Cases
- ✅ `-p 999999` — "Process 999999 not found" with helpful message
- ✅ No arguments — Shows full help text

---

## What's Broken (All Fixed)

### 1. JSON output crashes on bytes serialization ❌ → ✅ FIXED
**Error:** `Object of type bytes is not JSON serializable`  
**Cause:** Scan results include a `raw` field of type `bytes`, which `json.dumps` can't serialize.  
**Fix:** Added `_sanitize_for_json()` helper that converts bytes to hex strings.

### 2. CSV output shows Python byte repr ❌ → ✅ FIXED
**Error:** `b'\x00\x00\x00\x00'` in CSV output instead of clean hex  
**Cause:** Same bytes serialization issue in CSV formatter.  
**Fix:** Added `_sanitize_for_csv()` helper that converts bytes to hex strings.

### 3. Bad AOB pattern crashes with cryptic error ❌ → ✅ FIXED
**Error:** `invalid literal for int() with base 16: 'invalid'`  
**Cause:** `parse_bytes()` calls `int(p, 16)` without error handling for non-hex input.  
**Fix:** Wrapped in try/except with descriptive error message explaining valid format.

### 4. String scan returns 0 for valid strings ❌ → ✅ FIXED
**Error:** `--value "bash" --type string` found 0 results in a bash process  
**Cause:** Default `fast_scan=True` only scans writable regions. Strings like "bash" live in read-only text segments.  
**Fix:** Added substring search for `STRING`, `STRING_UTF16`, and `BYTES` types in `_scan_chunk()`. Strings now searched across all readable regions.

---

## What Needs Manual Intervention

### Root/Sudo Required
- All memory read/write operations require elevated privileges
- ptrace attach needs `CAP_SYS_PTRACE` or root
- `/proc/pid/mem` access requires same UID or root

### Platform-Specific
- Windows injection (`--dll`, `--inject`) only works on Windows
- Lua injection requires actual Roblox process with accessible Lua VM
- ptrace operations are Linux-only

### Anti-Cheat Considerations
- Roblox Lua injection may be blocked by Byfron/Hyperion anti-cheat
- Memory scanning of protected processes may be detected

---

## Bugs Found and Fixed

| # | Description | Root Cause | Fix |
|---|-------------|-----------|-----|
| 1 | JSON output crashes | `bytes` not JSON-serializable | `_sanitize_for_json()` in `cli/output.py` |
| 2 | CSV raw field ugly | `bytes` repr in CSV | `_sanitize_for_csv()` in `cli/output.py` |
| 3 | Bad AOB pattern crash | Uncaught `ValueError` in `parse_bytes()` | Try/except with descriptive error in `utils/types.py` |
| 4 | String scan finds nothing | Only scanned writable regions | Added string/bytes substring search in `scanner/memory.py` |

### Improvements Added

| Feature | Description |
|---------|-------------|
| `--safe` mode | New flag that prevents all memory writes with clear warning |
| Better error messages | Permission denied, PID not found, invalid pattern all have actionable guidance |
| String scanning | Proper substring search for `string`, `string_utf16`, `bytes` types |
| JSON/CSV sanitization | Clean hex output instead of Python byte repr |

---

## Recommended Next Improvements

1. **Chunked memory reads with ctypes** — Use `ctypes` to call `process_vm_readv` on Linux for faster reads than Python file I/O
2. **Page-aligned scanning** — Skip non-readable pages more efficiently using `/proc/pid/maps` metadata
3. **Pointer chain following** — Multi-level pointer dereference with offset display
4. **Result limiting** — Cap output at N results with `--limit` flag (641K results is unwieldy)
5. **Progress bar** — Show scan progress for large memory spaces
6. **Snapshot diff** — Compare two scans side-by-side with colored diffs
7. **Address bookmarks** — Save and name frequently-accessed addresses
8. **Freeze mode** — Continuously write a value in a background thread
9. **Windows support testing** — The Windows code paths exist but are untested
10. **Performance profiling** — Identify bottlenecks in large scans
