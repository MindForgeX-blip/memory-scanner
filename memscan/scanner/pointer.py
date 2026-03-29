"""
memscan/scanner/pointer.py — Pointer scanning and traversal.

Implements pointer chain resolution, pointer map generation,
and backtracing to find static base addresses (module + offset).
"""

import struct
from utils.types import type_size, unpack_value


class PointerScanner:
    """
    Pointer scanner for resolving dynamic addresses to static pointers.
    
    Can:
    - Read a pointer chain (multi-level pointer dereference)
    - Find what addresses point to a target
    - Generate a pointer map for a memory range
    - Resolve addresses back to module base + offset
    """

    def __init__(self, memory_scanner, proc_manager, proc_info, logger):
        """
        Args:
            memory_scanner: MemoryScanner instance
            proc_manager: ProcessManager instance
            proc_info: ProcessInfo object
            logger: Logger instance
        """
        self.memory = memory_scanner
        self.proc_manager = proc_manager
        self.proc_info = proc_info
        self.logger = logger
        self._pointer_size = 8 if proc_info.arch.value == 64 else 4

    def read_pointer(self, address):
        """
        Read a pointer value from memory.
        
        Args:
            address: Address to read the pointer from
        
        Returns:
            int: Dereferenced pointer value, or 0 on failure
        """
        data = self.memory.read_memory(address, self._pointer_size)
        if not data or len(data) < self._pointer_size:
            return 0
        
        if self._pointer_size == 8:
            return struct.unpack("<Q", data)[0]
        else:
            return struct.unpack("<I", data)[0]

    def trace_pointer_chain(self, base_address, offsets):
        """
        Follow a multi-level pointer chain.
        
        Example: trace_pointer_chain(module_base, [0x10, 0x20, 0x30])
        Reads: [[module_base + 0x10] + 0x20] + 0x30
        
        Args:
            base_address: Starting address
            offsets: list of int offsets to follow
        
        Returns:
            int: Final address, or 0 if chain breaks
        """
        current = base_address
        self.logger.debug(f"Pointer chain start: 0x{current:016X}")
        
        for i, offset in enumerate(offsets):
            ptr = self.read_pointer(current)
            if ptr == 0:
                self.logger.debug(f"Pointer chain broke at level {i} (0x{current:016X})")
                return 0
            current = ptr + offset
            self.logger.debug(f"  Level {i}: *0x{ptr:016X} + 0x{offset:X} = 0x{current:016X}")
        
        return current

    def find_pointers_to(self, target_address, start, end, max_results=100):
        """
        Find all pointers in a memory range that point to target_address.
        
        Args:
            target_address: The address we want pointers to
            start: Start of scan range
            end: End of scan range
            max_results: Stop after finding this many
        
        Returns:
            list of dicts: [{"address": int, "value": int}, ...]
        """
        self.logger.info(f"Scanning for pointers to 0x{target_address:016X}")
        self.logger.info(f"Range: 0x{start:016X} - 0x{end:016X}")
        
        results = []
        ptr_bytes = struct.pack("<Q" if self._pointer_size == 8 else "<I", target_address)
        
        addr = start
        while addr < end and len(results) < max_results:
            # Read in 1MB chunks
            chunk_size = min(1024 * 1024, end - addr)
            data = self.memory.read_memory(addr, chunk_size)
            
            if data:
                # Search for pointer value in this chunk
                offset = 0
                while True:
                    idx = data.find(ptr_bytes, offset)
                    if idx == -1:
                        break
                    match_addr = addr + idx
                    results.append({
                        "address": match_addr,
                        "value": target_address
                    })
                    offset = idx + self._pointer_size
            
            addr += chunk_size
        
        self.logger.info(f"Found {len(results)} pointers to 0x{target_address:016X}")
        return results

    def resolve_to_module(self, address):
        """
        Resolve a dynamic address back to module base + offset.
        
        Args:
            address: The address to resolve
        
        Returns:
            dict: {"module": str, "base": int, "offset": int} or None
        """
        modules = self.proc_manager.get_modules(self.proc_info)
        
        for mod in modules:
            base = mod["base"]
            size = mod.get("size", 0xFFFFFFFF)
            if base <= address < base + size:
                offset = address - base
                return {
                    "module": mod["name"],
                    "base": base,
                    "offset": offset,
                    "offset_hex": f"+0x{offset:X}"
                }
        
        return None

    def generate_pointer_map(self, start, end, max_depth=3):
        """
        Generate a pointer map for a memory region.
        
        Finds all pointers within the range that point to addresses
        also within the range. This can help identify data structures.
        
        Args:
            start: Start of memory range
            end: End of memory range
            max_depth: Maximum pointer chain depth to explore
        
        Returns:
            list of dicts with pointer information
        """
        self.logger.info(f"Generating pointer map for 0x{start:016X} - 0x{end:016X}")
        
        pointer_map = []
        addr = start
        
        while addr < end:
            chunk_size = min(1024 * 1024, end - addr)
            data = self.memory.read_memory(addr, chunk_size)
            
            if data:
                for i in range(0, len(data) - self._pointer_size + 1, self._pointer_size):
                    if self._pointer_size == 8:
                        ptr_val = struct.unpack("<Q", data[i:i + 8])[0]
                    else:
                        ptr_val = struct.unpack("<I", data[i:i + 4])[0]
                    
                    # Check if pointer is within our range
                    if start <= ptr_val < end:
                        source = addr + i
                        pointer_map.append({
                            "source": source,
                            "target": ptr_val,
                            "offset": ptr_val - start
                        })
            
            addr += chunk_size
        
        self.logger.info(f"Pointer map: {len(pointer_map)} entries found")
        return pointer_map
