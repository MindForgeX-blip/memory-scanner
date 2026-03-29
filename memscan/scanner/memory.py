"""
memscan/scanner/memory.py — Memory reading, writing, and scanning.

Core memory operations: read/write process memory, scan for values
across memory regions, and manage virtual memory page enumeration.
"""

import os
import sys
import platform
import ctypes
import struct
import time
from enum import Enum

from utils.types import DataType, parse_value, unpack_value, type_size, parse_bytes


class ScanType(Enum):
    """Types of value scans."""
    EXACT = "exact"
    GREATER = "greater"
    LESS = "less"
    BETWEEN = "between"
    INCREASED = "increased"
    DECREASED = "decreased"
    CHANGED = "changed"
    UNCHANGED = "unchanged"
    AOB = "aob"  # Array of bytes pattern


class MemoryRegion:
    """Represents a virtual memory region in a process."""
    def __init__(self, base, size, readable=False, writable=False, executable=False, name=""):
        self.base = base
        self.size = size
        self.readable = readable
        self.writable = writable
        self.executable = executable
        self.name = name

    def __repr__(self):
        perms = ("r" if self.readable else "-") + ("w" if self.writable else "-") + ("x" if self.executable else "-")
        return f"MemoryRegion(0x{self.base:016X} - 0x{self.base + self.size:016X} [{perms}] {self.name})"


class MemoryScanner:
    """
    Core memory scanner for reading, writing, and scanning process memory.
    
    Uses /proc/<pid>/mem on Linux and ReadProcessMemory/WriteProcessMemory on Windows.
    """

    # Scan result entry: (address, current_value, previous_value)
    ScanResult = None  # Set to tuple in scan()

    def __init__(self, proc_info, proc_manager, logger, safe_mode=False):
        """
        Args:
            proc_info: ProcessInfo object (must be attached)
            proc_manager: ProcessManager instance
            logger: Logger instance
            safe_mode: If True, never write to memory
        """
        self.proc_info = proc_info
        self.proc_manager = proc_manager
        self.logger = logger
        self.os_type = platform.system().lower()
        self.safe_mode = safe_mode
        
        # Store previous scan results for refinement
        self._previous_results = []
        self._previous_values = {}  # address -> previous raw bytes
        
        # File handle for /proc/<pid>/mem on Linux
        self._mem_fd = None

    def _open_mem(self):
        """Open the process memory file for reading on Linux."""
        if self.os_type == "linux":
            mem_path = f"/proc/{self.proc_info.pid}/mem"
            try:
                self._mem_fd = open(mem_path, "rb", buffering=0)
                return True
            except PermissionError:
                self.logger.error(
                    f"Permission denied reading {mem_path}. "
                    "Run with sudo for process memory access."
                )
                return False
            except FileNotFoundError:
                self.logger.error(
                    f"Process {self.proc_info.pid} not found. "
                    "Use 'memscan list' to see running processes."
                )
                return False
        return True

    def _close_mem(self):
        """Close the memory file handle."""
        if self._mem_fd:
            self._mem_fd.close()
            self._mem_fd = None

    def read_memory(self, address, size):
        """
        Read bytes from process memory.
        
        Args:
            address: Virtual address to read from
            size: Number of bytes to read
        
        Returns:
            bytes or None on failure
        """
        try:
            if self.os_type == "linux":
                return self._read_linux(address, size)
            elif self.os_type == "windows":
                return self._read_windows(address, size)
        except Exception as e:
            self.logger.debug(f"Read failed at 0x{address:016X}: {e}")
            return None

    def write_memory(self, address, data):
        """
        Write bytes to process memory.
        
        Args:
            address: Virtual address to write to
            data: bytes to write
        
        Returns:
            True on success, False on failure
        """
        if self.safe_mode:
            self.logger.warning(
                f"Write blocked by --safe mode. "
                f"Remove --safe flag to allow memory writes."
            )
            return False
        
        try:
            if self.os_type == "linux":
                return self._write_linux(address, data)
            elif self.os_type == "windows":
                return self._write_windows(address, data)
        except Exception as e:
            self.logger.error(f"Write failed at 0x{address:016X}: {e}")
            return False

    def _read_linux(self, address, size):
        """Read memory from a Linux process via /proc/<pid>/mem."""
        if not self._mem_fd:
            if not self._open_mem():
                return None
        
        try:
            self._mem_fd.seek(address)
            data = self._mem_fd.read(size)
            if len(data) != size:
                self.logger.debug(f"Short read at 0x{address:016X}: got {len(data)}/{size} bytes")
            return data if data else None
        except (OSError, IOError) as e:
            self.logger.debug(
                f"Cannot read memory at 0x{address:016X}: {e}. "
                "Page may not be readable. Try --safe mode."
            )
            return None

    def _write_linux(self, address, data):
        """Write memory to a Linux process via /proc/<pid>/mem."""
        mem_path = f"/proc/{self.proc_info.pid}/mem"
        try:
            with open(mem_path, "r+b", buffering=0) as f:
                f.seek(address)
                f.write(data)
            return True
        except PermissionError:
            self.logger.error(
                f"Permission denied writing to PID {self.proc_info.pid}. "
                "Run with sudo for process memory access."
            )
            return False
        except (OSError, IOError) as e:
            self.logger.error(
                f"Cannot write memory at 0x{address:016X}: {e}. "
                "Page may not be writable."
            )
            return False

    def _read_windows(self, address, size):
        """Read memory from a Windows process via ReadProcessMemory."""
        try:
            import ctypes.wintypes
            kernel32 = ctypes.windll.kernel32
            handle = self.proc_info._handle
            if not handle:
                self.logger.error("Not attached to process")
                return None
            
            buf = ctypes.create_string_buffer(size)
            bytes_read = ctypes.c_size_t(0)
            result = kernel32.ReadProcessMemory(
                handle, ctypes.c_void_p(address), buf, size, ctypes.byref(bytes_read)
            )
            if result:
                return buf.raw[:bytes_read.value]
            return None
        except Exception as e:
            self.logger.debug(f"ReadProcessMemory failed: {e}")
            return None

    def _write_windows(self, address, data):
        """Write memory to a Windows process via WriteProcessMemory."""
        try:
            import ctypes.wintypes
            kernel32 = ctypes.windll.kernel32
            handle = self.proc_info._handle
            if not handle:
                self.logger.error("Not attached to process")
                return False
            
            buf = ctypes.create_string_buffer(data)
            bytes_written = ctypes.c_size_t(0)
            result = kernel32.WriteProcessMemory(
                handle, ctypes.c_void_p(address), buf, len(data), ctypes.byref(bytes_written)
            )
            return bool(result)
        except Exception as e:
            self.logger.error(f"WriteProcessMemory failed: {e}")
            return False

    def get_regions(self, writable_only=False):
        """
        Enumerate virtual memory regions for the process.
        
        Args:
            writable_only: If True, only return writable regions
        
        Returns:
            list of MemoryRegion
        """
        regions = []
        
        if self.os_type == "linux":
            maps_path = f"/proc/{self.proc_info.pid}/maps"
            try:
                with open(maps_path, "r") as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) < 5:
                            continue
                        
                        addr_range = parts[0].split("-")
                        base = int(addr_range[0], 16)
                        end = int(addr_range[1], 16)
                        perms = parts[1]
                        
                        readable = "r" in perms
                        writable = "w" in perms
                        executable = "x" in perms
                        
                        if writable_only and not writable:
                            continue
                        
                        name = parts[-1] if len(parts) >= 6 else ""
                        regions.append(MemoryRegion(
                            base, end - base,
                            readable, writable, executable,
                            name
                        ))
            except (FileNotFoundError, PermissionError) as e:
                self.logger.error(f"Cannot read memory maps: {e}")
        
        elif self.os_type == "windows":
            try:
                import ctypes.wintypes
                
                kernel32 = ctypes.windll.kernel32
                handle = self.proc_info._handle
                
                MEMORY_BASIC_INFORMATION = ctypes.c_byte * 48  # Approximate size
                MEM_COMMIT = 0x1000
                PAGE_READWRITE = 0x04
                PAGE_EXECUTE_READWRITE = 0x40
                PAGE_READONLY = 0x02
                PAGE_EXECUTE_READ = 0x20
                
                addr = 0
                max_addr = (1 << 64) - 1 if self.proc_info.arch.value == 64 else (1 << 32) - 1
                
                while addr < max_addr:
                    mbi = MEMORY_BASIC_INFORMATION()
                    result = kernel32.VirtualQueryEx(
                        handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)
                    )
                    if result == 0:
                        break
                    
                    # Parse MBI (simplified — actual layout depends on arch)
                    # For full support, use a proper struct definition
                    regions.append(MemoryRegion(addr, 4096))  # Placeholder
                    addr += 4096
            except Exception as e:
                self.logger.warning(f"VirtualQueryEx failed: {e}")
        
        return regions

    def scan(self, scan_type, value=None, dtype=DataType.INT32, value2=None,
             regions=None, fast_scan=True):
        """
        Scan process memory for a value.
        
        Args:
            scan_type: ScanType enum
            value: Primary value to scan for (bytes or raw for AOB)
            dtype: DataType to interpret memory as
            value2: Secondary value for range scans (between)
            regions: List of MemoryRegion to scan (None = all writable)
            fast_scan: If True, only scan writable+readable regions
        
        Returns:
            list of dicts: [{"address": int, "value": str, "raw": bytes}, ...]
        """
        if regions is None:
            regions = self.get_regions(writable_only=fast_scan)
        
        results = []
        total_regions = len(regions)
        
        self.logger.info(f"Scanning {total_regions} memory regions...")
        
        for i, region in enumerate(regions):
            if not region.readable:
                continue
            
            self.logger.debug(f"Scanning region {i+1}/{total_regions}: {region}")
            
            # Read in chunks to handle large regions
            chunk_size = min(region.size, 4 * 1024 * 1024)  # 4MB chunks
            offset = 0
            
            while offset < region.size:
                read_size = min(chunk_size, region.size - offset)
                data = self.read_memory(region.base + offset, read_size)
                
                if data:
                    chunk_results = self._scan_chunk(
                        data, region.base + offset, scan_type,
                        value, dtype, value2
                    )
                    results.extend(chunk_results)
                
                offset += read_size
        
        self.logger.info(f"Scan complete: {len(results)} results found")
        
        # Store for refinement
        self._previous_results = results
        self._previous_values = {}
        for r in results:
            raw = self.read_memory(r["address"], type_size(dtype) or len(r.get("raw", b"")))
            if raw:
                self._previous_values[r["address"]] = raw
        
        return results

    def _scan_chunk(self, data, base_addr, scan_type, value, dtype, value2):
        """
        Scan a chunk of memory for matching values.
        """
        results = []
        
        if scan_type == ScanType.AOB:
            # AOB pattern scan — value is a list of int|None
            pattern = value  # list from parse_bytes()
            pattern_len = len(pattern)
            
            for i in range(len(data) - pattern_len + 1):
                match = True
                for j, p in enumerate(pattern):
                    if p is not None and data[i + j] != p:
                        match = False
                        break
                if match:
                    addr = base_addr + i
                    matched_bytes = data[i:i + pattern_len]
                    results.append({
                        "address": addr,
                        "value": matched_bytes.hex(),
                        "raw": matched_bytes
                    })
            return results
        
        # Value-based scanning
        val_size = type_size(dtype)
        if val_size == 0:
            # Variable-length type — string scanning uses substring search
            if dtype == DataType.STRING:
                needle = str(value).encode("ascii") if isinstance(value, str) else value
                if isinstance(needle, bytes):
                    offset = 0
                    while True:
                        idx = data.find(needle, offset)
                        if idx == -1:
                            break
                        results.append({
                            "address": base_addr + idx,
                            "value": data[idx:idx+len(needle)].decode("ascii", errors="replace"),
                            "raw": data[idx:idx+len(needle)]
                        })
                        offset = idx + 1
            elif dtype == DataType.STRING_UTF16:
                needle = str(value).encode("utf-16-le") if isinstance(value, str) else value
                if isinstance(needle, bytes):
                    offset = 0
                    while True:
                        idx = data.find(needle, offset)
                        if idx == -1:
                            break
                        results.append({
                            "address": base_addr + idx,
                            "value": data[idx:idx+len(needle)].decode("utf-16-le", errors="replace"),
                            "raw": data[idx:idx+len(needle)]
                        })
                        offset = idx + 1
            elif dtype == DataType.BYTES:
                # value is already a list of int|None from parse_bytes
                pattern = value
                pattern_len = len(pattern)
                for i in range(len(data) - pattern_len + 1):
                    match = True
                    for j, p in enumerate(pattern):
                        if p is not None and data[i + j] != p:
                            match = False
                            break
                    if match:
                        results.append({
                            "address": base_addr + i,
                            "value": data[i:i + pattern_len].hex(),
                            "raw": data[i:i + pattern_len]
                        })
            return results
        
        for i in range(0, len(data) - val_size + 1):
            chunk = data[i:i + val_size]
            addr = base_addr + i
            
            try:
                current_val = unpack_value(chunk, dtype)
            except Exception:
                continue
            
            match = False
            
            if scan_type == ScanType.EXACT:
                target = unpack_value(value, dtype)
                match = (current_val == target)
            elif scan_type == ScanType.GREATER:
                target = unpack_value(value, dtype)
                match = (current_val > target)
            elif scan_type == ScanType.LESS:
                target = unpack_value(value, dtype)
                match = (current_val < target)
            elif scan_type == ScanType.BETWEEN:
                target1 = unpack_value(value, dtype)
                target2 = unpack_value(value2, dtype)
                match = (target1 <= current_val <= target2)
            elif scan_type == ScanType.UNCHANGED:
                if addr in self._previous_values:
                    prev = unpack_value(self._previous_values[addr], dtype)
                    match = (current_val == prev)
            elif scan_type == ScanType.CHANGED:
                if addr in self._previous_values:
                    prev = unpack_value(self._previous_values[addr], dtype)
                    match = (current_val != prev)
            elif scan_type == ScanType.INCREASED:
                if addr in self._previous_values:
                    prev = unpack_value(self._previous_values[addr], dtype)
                    match = (current_val > prev)
            elif scan_type == ScanType.DECREASED:
                if addr in self._previous_values:
                    prev = unpack_value(self._previous_values[addr], dtype)
                    match = (current_val < prev)
            
            if match:
                results.append({
                    "address": addr,
                    "value": current_val,
                    "raw": chunk
                })
        
        return results

    def refine(self, scan_type, value=None, dtype=DataType.INT32, value2=None):
        """
        Refine previous scan results with a new filter.
        """
        if not self._previous_results:
            self.logger.warning("No previous scan results to refine. Run a scan first.")
            return []
        
        self.logger.info(f"Refining {len(self._previous_results)} previous results...")
        results = []
        val_size = type_size(dtype) or 4
        
        for prev in self._previous_results:
            addr = prev["address"]
            data = self.read_memory(addr, val_size)
            if not data:
                continue
            
            try:
                current_val = unpack_value(data, dtype)
            except Exception:
                continue
            
            match = False
            if scan_type == ScanType.EXACT:
                target = unpack_value(value, dtype)
                match = (current_val == target)
            elif scan_type == ScanType.GREATER:
                target = unpack_value(value, dtype)
                match = (current_val > target)
            elif scan_type == ScanType.LESS:
                target = unpack_value(value, dtype)
                match = (current_val < target)
            elif scan_type == ScanType.BETWEEN:
                target1 = unpack_value(value, dtype)
                target2 = unpack_value(value2, dtype)
                match = (target1 <= current_val <= target2)
            elif scan_type == ScanType.UNCHANGED:
                if addr in self._previous_values:
                    prev_val = unpack_value(self._previous_values[addr], dtype)
                    match = (current_val == prev_val)
            elif scan_type == ScanType.CHANGED:
                if addr in self._previous_values:
                    prev_val = unpack_value(self._previous_values[addr], dtype)
                    match = (current_val != prev_val)
            elif scan_type == ScanType.INCREASED:
                if addr in self._previous_values:
                    prev_val = unpack_value(self._previous_values[addr], dtype)
                    match = (current_val > prev_val)
            elif scan_type == ScanType.DECREASED:
                if addr in self._previous_values:
                    prev_val = unpack_value(self._previous_values[addr], dtype)
                    match = (current_val < prev_val)
            
            if match:
                results.append({
                    "address": addr,
                    "value": current_val,
                    "raw": data
                })
        
        # Update for next refinement
        self._previous_results = results
        self._previous_values = {}
        for r in results:
            raw = self.read_memory(r["address"], val_size)
            if raw:
                self._previous_values[r["address"]] = raw
        
        self.logger.info(f"Refinement complete: {len(results)} results remaining")
        return results

    def write_value(self, address, value, dtype):
        """
        Write a typed value to a specific address.
        """
        packed = parse_value(value, dtype)
        success = self.write_memory(address, packed)
        if success:
            self.logger.debug(f"Wrote {value} ({dtype.value}) to 0x{address:016X}")
        return success

    def write_bytes(self, address, byte_string):
        """
        Write raw bytes to a specific address.
        """
        byte_list = parse_bytes(byte_string)
        # Convert None wildcards to 0 (can't write wildcards)
        data = bytes(b if b is not None else 0 for b in byte_list)
        return self.write_memory(address, data)
