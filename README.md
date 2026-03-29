This project is a memory scanning and injection tool designed primarily for Linux environments. It allows inspection and modification of running processes, along with basic code injection capabilities. While partial support exists for Windows, it has not been fully tested. macOS is not supported.




Platform Support:
Feature	Linux	                      Windows	                          macOS
Process listing	✅ Supported	     ⚠️ Untested	                      ❌
Memory writing	✅ /proc/pid/mem	 ⚠️ WriteProcessMemory (untested)	  ❌
Code injection	✅ ptrace	         ⚠️ CreateRemoteThread (untested)	  ❌
DLL injection	❌ Not available	 ⚠️ Exists (untested)	              ❌
Lua injection	⚠️ Partial           ⚠️ Partial	                          ❌


Note:
This project is primarily developed and tested on Linux.
Windows support is experimental. macOS is not supported.


Anti-Cheat Compatibility:
Anti-Cheat Type	Memory Scan	Memory Write	Injection
None (offline / single-player)	✅	✅	✅
Basic (EAC / BattlEye - limited setups)	⚠️ Partial	❌	❌
Kernel-level (Vanguard / Hyperion)	❌	❌	❌
Limitations


Modern anti-cheat systems—especially kernel-level protections—operate with higher privileges than this tool.

Why this matters:
This tool runs in user mode (Ring 3)
Advanced anti-cheats run in kernel mode (Ring 0)

Because of this, anti-cheat systems can:
Block memory access (ReadProcessMemory, /proc/pid/mem)
Detect debugger attachments (ptrace)
Prevent memory modification
Stop remote thread creation (injection)
Scan for known cheat signatures


Summary:
✅ Fully functional on Linux (no anti-cheat)
⚠️ Experimental on Windows
❌ Unsupported on macOS
❌ Ineffective against kernel-level anti-cheat systems





# memscan Quickstart Guide

## Installation

No installation needed — just run `python3 memscan.py` from the memscan directory.

```bash
cd memscan
python3 memscan.py --help
```

**Important:** Most operations require root privileges to read/write process memory.

```bash
sudo python3 memscan.py -p <PID> --value 100
```

---

## Finding and Changing a Value (Step by Step)

### Example: Finding and modifying a game's health value

**Step 1: Find the process**
```bash
$ memscan list --name game
    PID    Arch  Name
------------------------------------------------------------
   12345  64-bit  MyGame
```

**Step 2: First scan (find current health value)**
```bash
$ sudo memscan -p 12345 --value 100 --type int32 --save scan1.txt
[INFO] Scanning for 100 as int32 (exact)
[SUCCESS] Found 42 results
[SUCCESS] Results saved to scan1.txt
```

**Step 3: Take damage in-game, refine the scan**
```bash
$ sudo memscan -p 12345 --refine --value 85 --load scan1.txt --save scan2.txt
[INFO] Loaded 42 previous results from scan1.txt
[INFO] Refining 42 previous results...
[SUCCESS] 3 results remaining
[SUCCESS] Results saved to scan2.txt
```

**Step 4: Repeat refinement until you have few results (1-5)**
```bash
$ sudo memscan -p 12345 --refine --value 85 --load scan2.txt
```

**Step 5: Freeze health (write max value)**
```bash
$ sudo memscan -p 12345 --refine --write 9999 --load scan2.txt
[SUCCESS] Wrote to 1/3 addresses
```

---

## Scanning for Strings

Find text in process memory (e.g., usernames, file paths):

```bash
$ sudo memscan -p 12345 --value "player_name" --type string
```

---

## Finding Static Addresses (Survive Restart)

Dynamic addresses change every time a game restarts. Use pointer scanning to find static addresses.

**Step 1: Find the address using value scanning** (see above)

**Step 2: Use pointer scan to find base address**
```bash
$ sudo memscan -p 12345 --ptr-scan --start 0x400000 --end 0x7FF000000000
Pointer Map: 0x000000400000 - 0x0007FF000000000
        Source  →            Target     Offset
-------------------------------------------------------
0x00007FF123400000  →  0x00007FF123456789  +0x56789
```

**Step 3: The pointer chain gives you module base + offset**

**Step 4: Next time, use the base + offset directly**

---

## AOB (Array of Bytes) Pattern Scanning

Find specific byte patterns in memory. Use `??` for wildcard bytes:

```bash
# Find ELF headers
$ sudo memscan -p 12345 --pattern "7f 45 4c 46"

# Pattern with wildcards
$ sudo memscan -p 12345 --pattern "89 45 FC ?? 8B 45"
```

---

## Watching an Address for Changes

Monitor a specific memory address and get notified when it changes:

```bash
# Find the address first
$ sudo memscan -p 12345 --value 100 --save addr.txt

# Watch for changes (updates every 500ms)
$ sudo memscan -p 12345 --watch 0x7FF123456789 --interval 500

# Log changes to a file
$ sudo memscan -p 12345 --watch 0x7FF123456789 --interval 100 --log changes.txt
```

---

## Output Formats

```bash
# JSON output (for scripting)
$ sudo memscan -p 12345 --value 0 --json

# CSV output (for spreadsheets)
$ sudo memscan -p 12345 --value 0 --csv

# Raw output (for piping to other tools)
$ sudo memscan -p 12345 --value 0 --raw
```

---

## Safe Mode

Use `--safe` to prevent any memory writes (scan/read only):

```bash
$ sudo memscan -p 12345 --safe --value 100
```

If you accidentally try to write with `--safe`:
```
[WARNING] Write blocked by --safe mode. Remove --safe flag to allow memory writes.
```

---

## Writing to Memory

**Write to a specific address:**
```bash
$ sudo memscan -p 12345 --address 0x7FF123456789 --write 9999
```

**Write raw bytes:**
```bash
$ sudo memscan -p 12345 --address 0x7FF123456789 --bytes "90 90 90 90"
```

---

## Injecting Shellcode (Linux)

```bash
$ sudo memscan -p 12345 --inject shellcode.bin
```

---

## Data Types

| Type | Description | Size |
|------|-------------|------|
| `int8` | Signed byte | 1 byte |
| `int16` | Signed short | 2 bytes |
| `int32` | Signed int (default) | 4 bytes |
| `int64` | Signed long | 8 bytes |
| `uint8` | Unsigned byte | 1 byte |
| `uint16` | Unsigned short | 2 bytes |
| `uint32` | Unsigned int | 4 bytes |
| `uint64` | Unsigned long | 8 bytes |
| `float` | 32-bit float | 4 bytes |
| `double` | 64-bit float | 8 bytes |
| `string` | ASCII string | Variable |
| `string_utf16` | UTF-16 string | Variable |
| `bytes` | Raw bytes | Variable |
| `bool` | Boolean | 1 byte |

---

## Common Issues

**"Permission denied"**
→ Run with `sudo`. Process memory access requires elevated privileges.

**"Process not found"**
→ Use `memscan list` to see running processes. The PID may have changed.

**"No results found"**
→ Try a different value or scan type. The value might have changed between scans.

**"Write blocked by --safe mode"**
→ Remove the `--safe` flag if you want to write to memory.
