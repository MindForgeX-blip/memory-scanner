"""
memscan/cli/output.py — Output formatting helpers.

Provides formatting functions for scan results, process lists,
and other memscan output in various formats.
"""

import json
import csv
import sys
import io
from datetime import datetime
from utils.logger import OutputFormat


def _sanitize_for_json(obj):
    """Convert non-JSON-serializable types to strings."""
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, dict):
        return {k: _sanitize_for_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_for_json(i) for i in obj]
    return obj


def _sanitize_for_csv(obj):
    """Convert non-CSV-serializable types to strings."""
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, dict):
        return {k: _sanitize_for_csv(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_for_csv(i) for i in obj]
    return obj


def format_process_list(procs, fmt=OutputFormat.HUMAN):
    """
    Format a process list for display.
    """
    if fmt == OutputFormat.HUMAN:
        lines = [f"\n{'PID':>8}  {'Arch':>6}  {'Name'}"]
        lines.append("-" * 60)
        for p in procs:
            arch = f"{p.arch.value}-bit" if p.arch.value else "???"
            lines.append(f"{p.pid:>8}  {arch:>6}  {p.name}")
        lines.append(f"\n{len(procs)} processes found\n")
        return "\n".join(lines)
    
    elif fmt == OutputFormat.JSON:
        data = [{"pid": p.pid, "name": p.name, "arch": p.arch.value} for p in procs]
        return json.dumps(data, indent=2)
    
    elif fmt == OutputFormat.CSV:
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(["pid", "name", "arch"])
        for p in procs:
            writer.writerow([p.pid, p.name, p.arch.value])
        return out.getvalue()
    
    elif fmt == OutputFormat.RAW:
        return "\n".join(f"{p.pid} {p.name}" for p in procs)


def format_scan_results(results, fmt=OutputFormat.HUMAN, label="Scan Results"):
    """
    Format scan results for display.
    """
    if not results:
        return "No results found.\n"
    
    if fmt == OutputFormat.HUMAN:
        lines = [f"\n{'='*60}", f" {label} ({len(results)} results)", f"{'='*60}"]
        for r in results:
            addr = r.get("address", 0)
            val = r.get("value", "???")
            dtype = r.get("type", "")
            extra = f" ({dtype})" if dtype else ""
            if isinstance(addr, int):
                lines.append(f"  0x{addr:016X}  →  {val}{extra}")
            else:
                lines.append(f"  {addr}  →  {val}{extra}")
        lines.append(f"{'='*60}\n")
        return "\n".join(lines)
    
    elif fmt == OutputFormat.JSON:
        serializable = []
        for r in results:
            d = _sanitize_for_json(dict(r))
            if "address" in d and isinstance(d["address"], int):
                d["address"] = f"0x{d['address']:016X}"
            serializable.append(d)
        return json.dumps(serializable, indent=2)
    
    elif fmt == OutputFormat.CSV:
        out = io.StringIO()
        writer = csv.writer(out)
        if results:
            headers = list(results[0].keys())
            writer.writerow(headers)
            for r in results:
                row = []
                for h in headers:
                    v = _sanitize_for_csv(r.get(h, ""))
                    if isinstance(v, int) and h == "address":
                        v = f"0x{v:016X}"
                    row.append(v)
                writer.writerow(row)
        return out.getvalue()
    
    elif fmt == OutputFormat.RAW:
        lines = []
        for r in results:
            addr = r.get("address", 0)
            val = r.get("value", "")
            if isinstance(addr, int):
                lines.append(f"0x{addr:016X} {val}")
            else:
                lines.append(f"{addr} {val}")
        return "\n".join(lines)


def format_diff(results_old, results_new, fmt=OutputFormat.HUMAN):
    """
    Show differences between two scan result sets.
    """
    old_map = {r["address"]: r["value"] for r in results_old}
    new_map = {r["address"]: r["value"] for r in results_new}
    
    changes = []
    for addr in old_map:
        if addr in new_map:
            old_val = old_map[addr]
            new_val = new_map[addr]
            if old_val != new_val:
                changes.append({
                    "address": addr,
                    "old_value": old_val,
                    "new_value": new_val
                })
    
    if fmt == OutputFormat.HUMAN:
        lines = [f"\n{'='*60}", f" Changes ({len(changes)} modified)", f"{'='*60}"]
        for c in changes:
            addr = c["address"]
            if isinstance(addr, int):
                lines.append(f"  0x{addr:016X}  {c['old_value']} → {c['new_value']}")
            else:
                lines.append(f"  {addr}  {c['old_value']} → {c['new_value']}")
        lines.append(f"{'='*60}\n")
        return "\n".join(lines)
    
    elif fmt == OutputFormat.JSON:
        serializable = []
        for c in changes:
            d = _sanitize_for_json(dict(c))
            if isinstance(d.get("address"), int):
                d["address"] = f"0x{d['address']:016X}"
            serializable.append(d)
        return json.dumps(serializable, indent=2)
    
    return "\n".join(f"{c['address']} {c['old_value']} -> {c['new_value']}" for c in changes)


def save_results(results, filepath, fmt=OutputFormat.HUMAN):
    """
    Save scan results to a file.
    """
    content = format_scan_results(results, fmt, label="Saved Results")
    with open(filepath, "w") as f:
        f.write(content)
    return filepath


def load_results(filepath):
    """
    Load previously saved scan results from a file.
    """
    results = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("=") or line.startswith("S") or line.startswith("#"):
                    continue
                # Parse: "  0x00007FF123456789  →  42 (int32)"
                parts = line.replace("→", "->").split("->")
                if len(parts) >= 2:
                    addr_str = parts[0].strip()
                    val_str = parts[1].strip().split("(")[0].strip()
                    try:
                        addr = int(addr_str, 16)
                        # Try to parse as number
                        try:
                            val = int(val_str)
                        except ValueError:
                            try:
                                val = float(val_str)
                            except ValueError:
                                val = val_str
                        results.append({"address": addr, "value": val})
                    except ValueError:
                        continue
    except FileNotFoundError:
        pass
    return results
