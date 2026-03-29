"""
memscan/injector/linux.py — Linux code injection via ptrace.

Implements shellcode injection into Linux processes using ptrace
to write code into the target's memory and create a remote thread.
"""

import os
import sys
import ctypes
import ctypes.util
import struct
import signal


class LinuxInjector:
    """
    Code injector for Linux processes.
    
    Uses ptrace to:
    1. Write shellcode into a code cave or allocated memory
    2. Hijack a thread's instruction pointer to execute the shellcode
    3. Restore the original state after execution
    
    Requires root or CAP_SYS_PTRACE capability.
    """

    def __init__(self, proc_info, memory_scanner, logger):
        """
        Args:
            proc_info: ProcessInfo object (must be attached)
            memory_scanner: MemoryScanner instance
            logger: Logger instance
        """
        self.proc_info = proc_info
        self.memory = memory_scanner
        self.logger = logger
        self._libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        
        # ptrace request numbers (x86_64)
        self.PTRACE_POKEDATA = 2
        self.PTRACE_POKETEXT = 1
        self.PTRACE_PEEKDATA = 2
        self.PTRACE_PEEKTEXT = 1
        self.PTRACE_GETREGS = 12
        self.PTRACE_SETREGS = 13
        self.PTRACE_CONT = 7

    def inject_shellcode(self, shellcode):
        """
        Inject and execute shellcode in the target process.
        
        This works by:
        1. Saving the current register state
        2. Finding a location in the process's writable memory
        3. Writing the shellcode there via ptrace
        4. Setting RIP to point to our shellcode
        5. Continuing the process to execute it
        6. Restoring original registers
        
        Args:
            shellcode: bytes of machine code to inject
        
        Returns:
            True if injection succeeded
        """
        pid = self.proc_info.pid
        
        if not self.proc_info._attached:
            self.logger.error("Must attach to process before injecting")
            return False
        
        if self.proc_info.arch.value == 32 and len(shellcode) > 0:
            self.logger.warning("Injecting into 32-bit process — ensure shellcode is 32-bit")
        
        self.logger.info(f"Injecting {len(shellcode)} bytes of shellcode into PID {pid}")
        
        try:
            # Step 1: Get current register state
            regs = self._get_registers(pid)
            if not regs:
                self.logger.error("Failed to get register state")
                return False
            
            orig_rip = regs.rip if hasattr(regs, 'rip') else regs.eip
            self.logger.debug(f"Original RIP: 0x{orig_rip:016X}")
            
            # Step 2: Find writable memory region (use heap or stack)
            # We'll write into the process's mapped writable regions
            inject_addr = self._find_injection_point(pid)
            if not inject_addr:
                self.logger.error("Could not find suitable memory region for injection")
                return False
            
            self.logger.debug(f"Using injection address: 0x{inject_addr:016X}")
            
            # Step 3: Write shellcode via ptrace POKETEXT
            self._write_shellcode_ptrace(pid, inject_addr, shellcode)
            
            # Step 4: Set RIP to our shellcode
            if hasattr(regs, 'rip'):
                regs.rip = inject_addr
            else:
                regs.eip = inject_addr
            self._set_registers(pid, regs)
            
            # Step 5: Continue execution
            self._libc.ptrace(self.PTRACE_CONT, pid, 0, 0)
            
            self.logger.success(f"Shellcode injected and executing at 0x{inject_addr:016X}")
            
            # Step 6: Wait briefly, then restore
            try:
                os.waitpid(pid, os.WUNTRACED)
            except ChildProcessError:
                pass
            
            # Restore original RIP
            if hasattr(regs, 'rip'):
                regs.rip = orig_rip
            else:
                regs.eip = orig_rip
            self._set_registers(pid, regs)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Injection failed: {e}")
            return False

    def inject_file(self, shellcode_path):
        """
        Load shellcode from a file and inject it.
        
        Args:
            shellcode_path: Path to binary shellcode file
        
        Returns:
            True if injection succeeded
        """
        try:
            with open(shellcode_path, "rb") as f:
                shellcode = f.read()
            self.logger.info(f"Loaded {len(shellcode)} bytes from {shellcode_path}")
            return self.inject_shellcode(shellcode)
        except FileNotFoundError:
            self.logger.error(f"Shellcode file not found: {shellcode_path}")
            return False
        except Exception as e:
            self.logger.error(f"Failed to read shellcode: {e}")
            return False

    def _get_registers(self, pid):
        """Get current register state via ptrace."""
        try:
            import struct as _struct
            
            # user_regs_struct for x86_64 (sizeof = 216 bytes on x86_64)
            class user_regs_struct(ctypes.Structure):
                _fields_ = [
                    ("r15", ctypes.c_ulonglong),
                    ("r14", ctypes.c_ulonglong),
                    ("r13", ctypes.c_ulonglong),
                    ("r12", ctypes.c_ulonglong),
                    ("rbp", ctypes.c_ulonglong),
                    ("rbx", ctypes.c_ulonglong),
                    ("r11", ctypes.c_ulonglong),
                    ("r10", ctypes.c_ulonglong),
                    ("r9", ctypes.c_ulonglong),
                    ("r8", ctypes.c_ulonglong),
                    ("rax", ctypes.c_ulonglong),
                    ("rcx", ctypes.c_ulonglong),
                    ("rdx", ctypes.c_ulonglong),
                    ("rsi", ctypes.c_ulonglong),
                    ("rdi", ctypes.c_ulonglong),
                    ("orig_rax", ctypes.c_ulonglong),
                    ("rip", ctypes.c_ulonglong),
                    ("cs", ctypes.c_ulonglong),
                    ("eflags", ctypes.c_ulonglong),
                    ("rsp", ctypes.c_ulonglong),
                    ("ss", ctypes.c_ulonglong),
                    ("fs_base", ctypes.c_ulonglong),
                    ("gs_base", ctypes.c_ulonglong),
                    ("ds", ctypes.c_ulonglong),
                    ("es", ctypes.c_ulonglong),
                    ("fs", ctypes.c_ulonglong),
                    ("gs", ctypes.c_ulonglong),
                ]
            
            regs = user_regs_struct()
            result = self._libc.ptrace(self.PTRACE_GETREGS, pid, 0, ctypes.byref(regs))
            if result != 0:
                return None
            return regs
        except Exception as e:
            self.logger.debug(f"get_registers failed: {e}")
            return None

    def _set_registers(self, pid, regs):
        """Set register state via ptrace."""
        result = self._libc.ptrace(self.PTRACE_SETREGS, pid, 0, ctypes.byref(regs))
        return result == 0

    def _find_injection_point(self, pid):
        """
        Find a suitable memory address to inject shellcode into.
        
        Looks for writable anonymous memory (heap, stack, or anon mmap).
        
        Returns:
            int: address or None
        """
        maps_path = f"/proc/{pid}/maps"
        try:
            with open(maps_path, "r") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) < 5:
                        continue
                    perms = parts[1]
                    # Look for large writable anonymous region
                    if "w" in perms and "x" not in perms:
                        addr_range = parts[0].split("-")
                        base = int(addr_range[0], 16)
                        end = int(addr_range[1], 16)
                        if end - base >= 4096:  # At least a page
                            return base + 0x100  # Offset a bit from base
        except Exception:
            pass
        return None

    def _write_shellcode_ptrace(self, pid, addr, shellcode):
        """Write shellcode to target memory via ptrace POKETEXT."""
        word_size = 8  # 64-bit
        i = 0
        while i < len(shellcode):
            # Pack up to word_size bytes into a c_ulong
            chunk = shellcode[i:i + word_size]
            # Pad to word size
            chunk += b"\x00" * (word_size - len(chunk))
            word = struct.unpack("<Q", chunk)[0]
            
            result = self._libc.ptrace(self.PTRACE_POKETEXT, pid, addr + i, word)
            if result != 0:
                errno = ctypes.get_errno()
                self.logger.warning(f"POKETEXT failed at offset {i} (errno={errno})")
            
            i += word_size
