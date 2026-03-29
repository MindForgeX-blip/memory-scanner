"""
memscan/logger.py — Logging utilities for memscan.

Provides structured logging with support for different output formats
(human-readable, JSON, CSV, raw). Each log message includes a timestamp
and severity level.
"""

import sys
import json
import csv
import io
from datetime import datetime
from enum import Enum


class LogLevel(Enum):
    """Severity levels for log messages."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    SUCCESS = "SUCCESS"


class OutputFormat(Enum):
    """Supported output formats."""
    HUMAN = "human"
    JSON = "json"
    CSV = "csv"
    RAW = "raw"


class Logger:
    """
    Centralized logger for memscan.

    Supports human-readable, JSON, CSV, and raw output formats.
    Routes messages to stderr (for status) or stdout (for data).
    """

    def __init__(self, output_format=OutputFormat.HUMAN, verbose=False, log_file=None):
        """
        Args:
            output_format: How to format output (human/json/csv/raw)
            verbose: If True, show DEBUG messages
            log_file: Optional path to also write logs to
        """
        self.format = output_format
        self.verbose = verbose
        self.log_file = log_file
        self._log_fh = None
        if log_file:
            self._log_fh = open(log_file, "a")

    def close(self):
        """Close the log file handle if open."""
        if self._log_fh:
            self._log_fh.close()

    def _write(self, msg, level=LogLevel.INFO, stream=sys.stderr):
        """Write a log message with timestamp and level prefix."""
        ts = datetime.now().isoformat()
        if self.format == OutputFormat.HUMAN:
            prefix = f"[{ts}] [{level.value}]"
            line = f"{prefix} {msg}"
            print(line, file=stream)
            if self._log_fh:
                print(line, file=self._log_fh)
        elif self.format == OutputFormat.RAW:
            print(msg, file=stream)
        elif self.format == OutputFormat.JSON:
            entry = {"timestamp": ts, "level": level.value, "message": msg}
            print(json.dumps(entry), file=stream)
        elif self.format == OutputFormat.CSV:
            # CSV output — just the message for pipe-friendly output
            print(msg, file=stream)

    def debug(self, msg):
        """Log a debug message (only shown in verbose mode)."""
        if self.verbose:
            self._write(msg, LogLevel.DEBUG)

    def info(self, msg):
        """Log an informational message."""
        self._write(msg, LogLevel.INFO)

    def warning(self, msg):
        """Log a warning message."""
        self._write(msg, LogLevel.WARNING)

    def error(self, msg):
        """Log an error message."""
        self._write(msg, LogLevel.ERROR)

    def success(self, msg):
        """Log a success message."""
        self._write(msg, LogLevel.SUCCESS)

    def data(self, data, label=None):
        """
        Output scan results or data in the chosen format.
        
        Args:
            data: list of dicts with address/value info
            label: optional label for human format
        """
        if self.format == OutputFormat.HUMAN:
            if label:
                print(f"\n{'='*60}", file=sys.stdout)
                print(f" {label}", file=sys.stdout)
                print(f"{'='*60}", file=sys.stdout)
            for item in data:
                addr = item.get("address", "???")
                val = item.get("value", "???")
                dtype = item.get("type", "")
                extra = f" ({dtype})" if dtype else ""
                print(f"  0x{addr:016X}  →  {val}{extra}", file=sys.stdout)
            if label:
                print(f"{'='*60}\n", file=sys.stdout)
        elif self.format == OutputFormat.JSON:
            # Convert addresses to hex strings for JSON readability
            serializable = []
            for item in data:
                d = dict(item)
                if "address" in d:
                    d["address"] = f"0x{d['address']:016X}"
                serializable.append(d)
            print(json.dumps(serializable, indent=2), file=sys.stdout)
        elif self.format == OutputFormat.CSV:
            writer = csv.writer(sys.stdout)
            if data:
                headers = list(data[0].keys())
                writer.writerow(headers)
                for item in data:
                    row = []
                    for h in headers:
                        v = item.get(h, "")
                        if isinstance(v, int) and h == "address":
                            v = f"0x{v:016X}"
                        row.append(v)
                    writer.writerow(row)
        elif self.format == OutputFormat.RAW:
            for item in data:
                addr = item.get("address", 0)
                val = item.get("value", "")
                print(f"0x{addr:016X} {val}", file=sys.stdout)
