"""
memscan/cli/commands.py — Argparse command handlers.

Defines the CLI argument structure and dispatches to the appropriate
scanner/injector/monitor operations.
"""

import argparse
import sys
import time
import os
import signal
import subprocess

from scanner.process import ProcessManager, ProcessInfo
from scanner.memory import MemoryScanner, ScanType
from scanner.patterns import PatternScanner
from scanner.pointer import PointerScanner
from utils.types import DataType, TYPE_MAP, parse_value, parse_bytes, parse_address, type_size, unpack_value
from utils.logger import Logger, OutputFormat
from cli.output import (
    format_process_list, format_scan_results, format_diff,
    save_results, load_results
)


def build_parser():
    """
    Build the full argparse parser with all subcommands.
    """
    parser = argparse.ArgumentParser(
        prog="memscan",
        description="memscan — CLI memory scanner and editor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  memscan list                          List all processes
  memscan list --name roblox            Filter processes by name
  memscan -p RobloxPlayerBeta           Attach to process by name
  memscan -p 12345 --value 100          Scan for value 100
  memscan -p 12345 --refine --value 50  Refine previous scan
  memscan -p 12345 --pattern "89 45 ??" AOB scan with wildcard
  memscan -p 12345 --write 9999         Write to found addresses
  memscan -p 12345 --addr 0x7FF... --write 9999  Write to specific address
  memscan -p 12345 --watch 0x7FF...     Watch address for changes
  memscan -p 12345 --inject shell.bin   Inject shellcode
  memscan -p 12345 --luax "print('hi')" Execute Lua in Roblox
        """
    )

    # Global options
    parser.add_argument("-p", "--process", dest="process",
                        help="Target process by PID or name")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose/debug output")
    parser.add_argument("--safe", action="store_true",
                        help="Safe mode: scan/read only, never write to memory")
    parser.add_argument("--json", action="store_const", const="json", dest="output_fmt",
                        help="Output in JSON format")
    parser.add_argument("--csv", action="store_const", const="csv", dest="output_fmt",
                        help="Output in CSV format")
    parser.add_argument("--raw", action="store_const", const="raw", dest="output_fmt",
                        help="Output in raw format (for piping)")
    parser.add_argument("--human", action="store_const", const="human", dest="output_fmt",
                        help="Human-readable output (default)")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- list command ---
    list_parser = subparsers.add_parser("list", help="List running processes")
    list_parser.add_argument("--name", help="Filter processes by name (substring match)")
    list_parser.add_argument("--pid", type=int, help="Show info for specific PID")
    list_parser.add_argument("--json", action="store_const", const="json", dest="output_fmt",
                            help="Output in JSON format")
    list_parser.add_argument("--csv", action="store_const", const="csv", dest="output_fmt",
                            help="Output in CSV format")
    list_parser.add_argument("--raw", action="store_const", const="raw", dest="output_fmt",
                            help="Output in raw format")
    list_parser.add_argument("--human", action="store_const", const="human", dest="output_fmt",
                            help="Human-readable output (default)")
    list_parser.add_argument("-v", "--verbose", action="store_true",
                            help="Enable verbose/debug output")

    # --- scan options (on main parser, not subcommand) ---
    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument("--value", help="Value to scan for (supports hex: 0xDEADBEEF)")
    scan_group.add_argument("--value2", help="Second value for range scans (between)")
    scan_group.add_argument("--type", dest="data_type", default="int32",
                           choices=list(TYPE_MAP.keys()),
                           help="Data type for scanning (default: int32)")
    scan_group.add_argument("--scan-type", dest="scan_type", default="exact",
                           choices=["exact", "greater", "less", "between",
                                   "increased", "decreased", "unchanged", "changed"],
                           help="Scan comparison type (default: exact)")
    scan_group.add_argument("--pattern", help="AOB pattern: '89 45 FC ?? 8B 45'")
    scan_group.add_argument("--refine", action="store_true",
                           help="Refine previous scan results instead of full scan")

    # --- write options ---
    write_group = parser.add_argument_group("Write Options")
    write_group.add_argument("--write", help="Write value to found/specified addresses")
    write_group.add_argument("--address", "--addr", dest="address",
                            help="Specific address to write to (hex: 0x...)")
    write_group.add_argument("--bytes", dest="write_bytes",
                            help="Write raw bytes: '89 45 FC'")
    write_group.add_argument("--write-int", type=int, dest="write_int",
                            help="Write as integer")
    write_group.add_argument("--write-float", type=float, dest="write_float",
                            help="Write as float")

    # --- watch/monitor options ---
    watch_group = parser.add_argument_group("Watch/Monitor Options")
    watch_group.add_argument("--watch", help="Address to watch for changes (hex)")
    watch_group.add_argument("--watchlist", help="File with addresses to watch")
    watch_group.add_argument("--interval", default="1000",
                            help="Polling interval in ms (default: 1000)")
    watch_group.add_argument("--log", dest="log_file",
                            help="Log changes to file")
    watch_group.add_argument("--on-change", dest="on_change",
                            help="Command to execute on change")

    # --- pointer options ---
    ptr_group = parser.add_argument_group("Pointer Options")
    ptr_group.add_argument("--ptr-scan", action="store_true",
                          help="Generate pointer map for address range")
    ptr_group.add_argument("--start", help="Start address for pointer scan")
    ptr_group.add_argument("--end", help="End address for pointer scan")
    ptr_group.add_argument("--tracer", action="store_true",
                          help="Find what writes to the watched address")

    # --- injection options ---
    inj_group = parser.add_argument_group("Injection Options")
    inj_group.add_argument("--inject", help="Inject shellcode from file")
    inj_group.add_argument("--luax", dest="lua_code",
                          help="Execute Lua code in Roblox")
    inj_group.add_argument("--hook", help="Function to hook")
    inj_group.add_argument("--callback", help="Callback library for hook")
    inj_group.add_argument("--dll", help="DLL to inject (Windows only)")

    # --- output options ---
    out_group = parser.add_argument_group("Output Options")
    out_group.add_argument("--save", help="Save results to file")
    out_group.add_argument("--load", help="Load previous results (for refine)")
    out_group.add_argument("--diff", action="store_true",
                          help="Show differences from previous scan")

    return parser


def run(args):
    """
    Main entry point — dispatch parsed args to handler functions.
    """
    # Determine output format
    fmt_str = args.output_fmt or "human"
    fmt = OutputFormat(fmt_str)
    
    # Initialize logger
    logger = Logger(output_format=fmt, verbose=args.verbose)
    
    try:
        # Handle 'list' subcommand first (doesn't need -p)
        if args.command == "list":
            return cmd_list(args, logger)
        
        # Everything else needs a target process
        if not args.process:
            logger.error("No target process specified. Use -p <PID|name> or run 'memscan list'")
            return 1
        
        # Initialize process manager
        pm = ProcessManager(logger)
        
        # Find and attach to process
        proc_info = pm.find_process(args.process)
        if not proc_info:
            return 1
        
        logger.info(f"Found: {proc_info}")
        
        # Attach to process
        if not pm.attach(proc_info):
            return 1
        
        logger.success(f"Attached to PID {proc_info.pid} ({proc_info.name})")
        
        # Initialize memory scanner (with safe mode if requested)
        safe_mode = getattr(args, 'safe', False)
        if safe_mode:
            logger.info("Safe mode enabled — memory writes are disabled")
        
        scanner = MemoryScanner(proc_info, pm, logger, safe_mode=safe_mode)
        
        # Dispatch to appropriate handler
        result = 0
        
        if args.inject:
            result = cmd_inject(args, proc_info, scanner, pm, logger)
        elif args.lua_code:
            result = cmd_lua(args, proc_info, scanner, logger)
        elif args.dll:
            result = cmd_dll_inject(args, proc_info, scanner, pm, logger)
        elif args.pattern:
            result = cmd_aob_scan(args, scanner, logger)
        elif args.ptr_scan:
            result = cmd_ptr_scan(args, scanner, pm, proc_info, logger)
        elif args.watch or args.watchlist:
            result = cmd_watch(args, scanner, pm, proc_info, logger)
        elif args.write is not None or args.write_bytes or args.write_int is not None or args.write_float is not None:
            result = cmd_write(args, scanner, logger)
        elif args.value or args.refine:
            result = cmd_scan(args, scanner, logger)
        elif args.diff:
            result = cmd_diff(args, scanner, logger)
        elif args.save:
            # Just save current results
            save_results(scanner._previous_results, args.save, fmt)
            logger.success(f"Results saved to {args.save}")
        else:
            logger.info("No action specified. Use --help for usage information.")
        
        # Detach
        pm.detach(proc_info)
        
        return result
        
    except KeyboardInterrupt:
        logger.info("\nInterrupted by user.")
        return 130
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1
    finally:
        logger.close()


def cmd_list(args, logger):
    """Handle 'memscan list' command."""
    pm = ProcessManager(logger)
    procs = pm.list_processes(name_filter=args.name)
    
    if args.pid:
        proc = pm.find_process(args.pid)
        if proc:
            procs = [proc]
            modules = pm.get_modules(proc)
            if modules:
                logger.info(f"Loaded modules ({len(modules)}):")
                for mod in modules[:20]:
                    logger.info(f"  0x{mod['base']:016X}  {mod['name']}")
                if len(modules) > 20:
                    logger.info(f"  ... and {len(modules) - 20} more")
        else:
            return 1
    
    fmt = OutputFormat(getattr(args, 'output_fmt', None) or "human")
    print(format_process_list(procs, fmt))
    return 0


def cmd_scan(args, scanner, logger):
    """Handle value scanning."""
    if args.refine:
        if not args.value:
            logger.error("--refine requires --value")
            return 1
        return _refine(args, scanner, logger)
    
    if not args.value:
        logger.error("No value specified. Use --value <value>")
        return 1
    
    # Parse value and type
    dtype = DataType(TYPE_MAP[args.data_type.lower()])
    scan_type = ScanType(args.scan_type)
    value = parse_value(args.value, dtype)
    value2 = None
    if args.value2:
        value2 = parse_value(args.value2, dtype)
    
    logger.info(f"Scanning for {args.value} as {dtype.value} ({scan_type.value})")
    
    results = scanner.scan(scan_type, value, dtype, value2)
    
    if not results:
        logger.info("No results found. Try a different scan type or value.")
        return 0
    
    # Output results
    fmt = OutputFormat(args.output_fmt or "human")
    print(format_scan_results(results, fmt))
    logger.success(f"Found {len(results)} results")
    
    # Save if requested
    if args.save:
        save_results(results, args.save, fmt)
        logger.success(f"Results saved to {args.save}")
    
    return 0


def _refine(args, scanner, logger):
    """Handle scan refinement."""
    if args.load:
        prev = load_results(args.load)
        if prev:
            scanner._previous_results = prev
            logger.info(f"Loaded {len(prev)} previous results from {args.load}")
        else:
            logger.error(f"Could not load results from {args.load}")
            return 1
    
    if not scanner._previous_results:
        logger.error("No previous scan results to refine. Run a scan first, or use --load.")
        return 1
    
    dtype = DataType(TYPE_MAP[args.data_type.lower()])
    scan_type = ScanType(args.scan_type)
    value = parse_value(args.value, dtype)
    value2 = None
    if args.value2:
        value2 = parse_value(args.value2, dtype)
    
    results = scanner.refine(scan_type, value, dtype, value2)
    
    if not results:
        logger.info("No results after refinement.")
        return 0
    
    fmt = OutputFormat(args.output_fmt or "human")
    print(format_scan_results(results, fmt, label="Refined Results"))
    logger.success(f"{len(results)} results remaining")
    
    if args.save:
        save_results(results, args.save, fmt)
        logger.success(f"Results saved to {args.save}")
    
    return 0


def cmd_aob_scan(args, scanner, logger):
    """Handle AOB pattern scanning."""
    # Validate pattern before scanning
    try:
        pattern = parse_bytes(args.pattern)
    except ValueError:
        logger.error(
            f"Invalid AOB pattern '{args.pattern}'. "
            "Use hex bytes separated by spaces, wildcards as ??. "
            "Example: '89 45 FC ?? 8B 45'"
        )
        return 1
    
    pattern_scanner = PatternScanner(scanner, logger)
    results = pattern_scanner.scan(args.pattern)
    
    if not results:
        logger.info("No pattern matches found.")
        return 0
    
    fmt = OutputFormat(args.output_fmt or "human")
    print(format_scan_results(results, fmt, label="AOB Pattern Results"))
    logger.success(f"Found {len(results)} pattern matches")
    
    if args.save:
        save_results(results, args.save, fmt)
        logger.success(f"Results saved to {args.save}")
    
    return 0


def cmd_write(args, scanner, logger):
    """Handle memory write operations."""
    dtype = DataType(TYPE_MAP[args.data_type.lower()])
    
    # Write to specific address
    if args.address:
        addr = parse_address(args.address)
        wrote = False
        
        if args.write is not None:
            if scanner.write_value(addr, args.write, dtype):
                logger.success(f"Wrote {args.write} ({dtype.value}) to 0x{addr:016X}")
                wrote = True
        
        if args.write_int is not None:
            if scanner.write_value(addr, str(args.write_int), DataType.INT32):
                logger.success(f"Wrote int32 {args.write_int} to 0x{addr:016X}")
                wrote = True
        
        if args.write_float is not None:
            if scanner.write_value(addr, str(args.write_float), DataType.FLOAT):
                logger.success(f"Wrote float {args.write_float} to 0x{addr:016X}")
                wrote = True
        
        if args.write_bytes:
            if scanner.write_bytes(addr, args.write_bytes):
                logger.success(f"Wrote bytes to 0x{addr:016X}")
                wrote = True
        
        if not wrote:
            logger.error("No value to write specified")
            return 1
        
        return 0
    
    # Write to all found addresses
    if not scanner._previous_results:
        logger.error("No addresses to write to. Run a scan first, or specify --address.")
        return 1
    
    count = 0
    for result in scanner._previous_results:
        addr = result["address"]
        success = False
        
        if args.write is not None:
            success = scanner.write_value(addr, args.write, dtype)
        elif args.write_int is not None:
            success = scanner.write_value(addr, str(args.write_int), DataType.INT32)
        elif args.write_float is not None:
            success = scanner.write_value(addr, str(args.write_float), DataType.FLOAT)
        elif args.write_bytes:
            success = scanner.write_bytes(addr, args.write_bytes)
        
        if success:
            count += 1
    
    logger.success(f"Wrote to {count}/{len(scanner._previous_results)} addresses")
    return 0


def cmd_watch(args, scanner, pm, proc_info, logger):
    """Handle address watching/monitoring."""
    interval_ms = int(args.interval)
    interval_sec = interval_ms / 1000.0
    
    addresses = []
    
    if args.watch:
        addresses.append(parse_address(args.watch))
    
    if args.watchlist:
        try:
            with open(args.watchlist, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        addresses.append(parse_address(line))
            logger.info(f"Loaded {len(addresses)} addresses from {args.watchlist}")
        except FileNotFoundError:
            logger.error(f"Watchlist file not found: {args.watchlist}")
            return 1
    
    if not addresses:
        logger.error("No addresses to watch. Use --watch or --watchlist.")
        return 1
    
    dtype = DataType(TYPE_MAP[args.data_type.lower()])
    read_size = type_size(dtype) or 4
    
    logger.info(f"Watching {len(addresses)} addresses (interval: {interval_ms}ms)")
    logger.info("Press Ctrl+C to stop.\n")
    
    log_fh = None
    if args.log_file:
        log_fh = open(args.log_file, "a")
    
    previous_values = {}
    
    # Initial read
    for addr in addresses:
        data = scanner.read_memory(addr, read_size)
        if data:
            try:
                val = unpack_value(data, dtype)
                previous_values[addr] = val
                logger.info(f"  0x{addr:016X} = {val}")
            except Exception:
                previous_values[addr] = data.hex()
    
    print()
    
    try:
        while True:
            time.sleep(interval_sec)
            for addr in addresses:
                data = scanner.read_memory(addr, read_size)
                if data:
                    try:
                        val = unpack_value(data, dtype)
                    except Exception:
                        val = data.hex()
                    
                    old_val = previous_values.get(addr)
                    if old_val != val:
                        msg = f"[CHANGE] 0x{addr:016X}: {old_val} → {val}"
                        logger.info(msg)
                        
                        if log_fh:
                            ts = time.strftime("%Y-%m-%d %H:%M:%S")
                            log_fh.write(f"[{ts}] {msg}\n")
                            log_fh.flush()
                        
                        if args.on_change:
                            try:
                                subprocess.Popen(
                                    args.on_change, shell=True,
                                    stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL
                                )
                            except Exception as e:
                                logger.warning(f"on-change command failed: {e}")
                        
                        previous_values[addr] = val
                        
    except KeyboardInterrupt:
        logger.info("\nStopped watching.")
    finally:
        if log_fh:
            log_fh.close()
    
    return 0


def cmd_ptr_scan(args, scanner, pm, proc_info, logger):
    """Handle pointer scanning."""
    ptr_scanner = PointerScanner(scanner, pm, proc_info, logger)
    
    if not args.start or not args.end:
        logger.error("--ptr-scan requires --start and --end addresses")
        return 1
    
    start = parse_address(args.start)
    end = parse_address(args.end)
    
    pointer_map = ptr_scanner.generate_pointer_map(start, end)
    
    if not pointer_map:
        logger.info("No pointers found in range.")
        return 0
    
    fmt = OutputFormat(args.output_fmt or "human")
    if fmt == OutputFormat.HUMAN:
        print(f"\nPointer Map: 0x{start:016X} - 0x{end:016X}")
        print(f"{'Source':>18}  →  {'Target':>18}  {'Offset':>10}")
        print("-" * 55)
        for entry in pointer_map[:100]:
            print(f"0x{entry['source']:016X}  →  0x{entry['target']:016X}  +0x{entry['offset']:X}")
        if len(pointer_map) > 100:
            print(f"... and {len(pointer_map) - 100} more entries")
        print()
    elif fmt == OutputFormat.JSON:
        import json
        serializable = [
            {"source": f"0x{e['source']:016X}", "target": f"0x{e['target']:016X}", "offset": e["offset"]}
            for e in pointer_map
        ]
        print(json.dumps(serializable, indent=2))
    
    logger.success(f"Found {len(pointer_map)} pointers")
    return 0


def cmd_inject(args, proc_info, scanner, pm, logger):
    """Handle shellcode injection."""
    import platform
    os_type = platform.system().lower()
    
    if os_type == "linux":
        from injector.linux import LinuxInjector
        injector = LinuxInjector(proc_info, scanner, logger)
    elif os_type == "windows":
        from injector.windows import WindowsInjector
        injector = WindowsInjector(proc_info, scanner, logger)
    else:
        logger.error(f"Unsupported OS: {os_type}")
        return 1
    
    if proc_info.arch.value == 32:
        logger.warning("Target is 32-bit — ensure shellcode is 32-bit compatible")
    
    success = injector.inject_file(args.inject)
    return 0 if success else 1


def cmd_lua(args, proc_info, scanner, logger):
    """Handle Lua script execution in Roblox."""
    from injector.lua import RobloxLuaInjector
    
    injector = RobloxLuaInjector(proc_info, scanner, logger)
    success = injector.execute_lua(args.lua_code)
    return 0 if success else 1


def cmd_dll_inject(args, proc_info, scanner, pm, logger):
    """Handle DLL injection (Windows only)."""
    import platform
    if platform.system().lower() != "windows":
        logger.error("DLL injection is only supported on Windows")
        return 1
    
    from injector.windows import WindowsInjector
    injector = WindowsInjector(proc_info, scanner, logger)
    success = injector.inject_dll(args.dll)
    return 0 if success else 1


def cmd_diff(args, scanner, logger):
    """Show diff between current and previous scan results."""
    if not scanner._previous_results:
        logger.error("No previous results to diff against.")
        return 1
    
    if not scanner._previous_values:
        logger.error("No previous values stored. Run a scan first.")
        return 1
    
    # Re-scan to get current values
    current_results = []
    dtype = DataType(DataType.INT32)  # Default
    val_size = 4
    
    for prev in scanner._previous_results:
        addr = prev["address"]
        data = scanner.read_memory(addr, val_size)
        if data:
            try:
                val = unpack_value(data, dtype)
            except Exception:
                val = data.hex()
            current_results.append({"address": addr, "value": val})
    
    # Build old results from stored values
    old_results = []
    for addr, raw_data in scanner._previous_values.items():
        try:
            val = unpack_value(raw_data, dtype)
        except Exception:
            val = raw_data.hex()
        old_results.append({"address": addr, "value": val})
    
    fmt = OutputFormat(args.output_fmt or "human")
    print(format_diff(old_results, current_results, fmt))
    return 0
