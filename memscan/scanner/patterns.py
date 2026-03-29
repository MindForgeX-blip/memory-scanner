"""
memscan/scanner/patterns.py — AOB (Array of Bytes) pattern scanning.

Provides high-level pattern matching functions for scanning
process memory with byte patterns that support wildcards.
"""

from utils.types import parse_bytes
from scanner.memory import ScanType


class PatternScanner:
    """
    Array of Bytes (AOB) pattern scanner.
    
    Supports patterns like:
      - "89 45 FC 8B 45" (exact bytes)
      - "89 45 FC ?? 8B 45" (wildcard byte)
      - "48 8B * 48 89" (wildcard byte, alternate syntax)
    """

    def __init__(self, memory_scanner, logger):
        """
        Args:
            memory_scanner: MemoryScanner instance
            logger: Logger instance
        """
        self.memory = memory_scanner
        self.logger = logger

    def scan(self, pattern_string):
        """
        Scan all readable memory for a byte pattern.
        
        Args:
            pattern_string: "89 45 FC ?? 8B 45" format
        
        Returns:
            list of dicts with "address" and "value" (hex string of matched bytes)
        """
        pattern = parse_bytes(pattern_string)
        self.logger.info(f"AOB scan for pattern: {pattern_string} ({len(pattern)} bytes)")
        
        return self.memory.scan(
            scan_type=ScanType.AOB,
            value=pattern,
            fast_scan=False  # AOB can be in any readable region
        )

    def find_all(self, pattern_string):
        """Alias for scan() — find all occurrences of a pattern."""
        return self.scan(pattern_string)

    def find_first(self, pattern_string):
        """
        Find only the first occurrence of a pattern.
        
        Args:
            pattern_string: Byte pattern
        
        Returns:
            dict with address and value, or None
        """
        results = self.scan(pattern_string)
        return results[0] if results else None
