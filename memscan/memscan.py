#!/usr/bin/env python3
"""
memscan — CLI memory scanner and editor

A powerful tool for scanning, reading, writing, and injecting code into
process memory. Works on Linux (via /proc and ptrace) and Windows (via
OpenProcess and ReadProcessMemory).

Usage:
    memscan list                       List all processes
    memscan -p <pid|name> --value X    Scan for value X
    memscan -p <pid|name> --refine     Refine previous scan
    memscan -p <pid|name> --write X    Write X to found addresses
    memscan -p <pid|name> --pattern    AOB pattern scan
    memscan -p <pid|name> --inject     Inject shellcode
    memscan -p <pid|name> --luax       Execute Lua in Roblox

Run 'memscan --help' for full usage information.
"""

import sys
import os

# Add the memscan directory to sys.path so all subpackages resolve
_memscan_dir = os.path.dirname(os.path.abspath(__file__))
if _memscan_dir not in sys.path:
    sys.path.insert(0, _memscan_dir)

from cli.commands import build_parser, run


def main():
    """Main entry point for memscan CLI."""
    parser = build_parser()
    args = parser.parse_args()
    
    # Show help if no arguments at all
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    
    # Handle 'list' as a subcommand OR as a positional arg
    # Also handle when output flags come before 'list'
    args = parser.parse_args()
    
    # If we have 'list' as a command, the output format from global args should propagate
    exit_code = run(args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
