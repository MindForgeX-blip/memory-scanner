"""
memscan/injector/windows.py — Windows code injection via CreateRemoteThread.

Implements shellcode injection into Windows processes using
VirtualAllocEx + WriteProcessMemory + CreateRemoteThread.
"""

import ctypes
import ctypes.wintypes


class WindowsInjector:
    """
    Code injector for Windows processes.
    
    Uses the classic Windows injection technique:
    1. VirtualAllocEx — allocate memory in target process
    2. WriteProcessMemory — write shellcode or DLL path
    3. CreateRemoteThread — execute code in target process
    
    Requires Administrator privileges.
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
        
        try:
            self.kernel32 = ctypes.windll.kernel32
        except AttributeError:
            self.kernel32 = None
            self.logger.warning("Windows kernel32 not available — injection will not work")

    def inject_shellcode(self, shellcode):
        """
        Inject and execute shellcode via CreateRemoteThread.
        
        Args:
            shellcode: bytes of machine code
        
        Returns:
            True if injection succeeded
        """
        if not self.kernel32:
            self.logger.error("Windows API not available")
            return False
        
        handle = self.proc_info._handle
        if not handle:
            self.logger.error("Not attached to process")
            return False
        
        self.logger.info(f"Injecting {len(shellcode)} bytes via CreateRemoteThread")
        
        try:
            # Constants
            MEM_COMMIT = 0x1000
            MEM_RESERVE = 0x2000
            PAGE_EXECUTE_READWRITE = 0x40
            
            # Step 1: Allocate memory in target
            addr = self.kernel32.VirtualAllocEx(
                handle, 0, len(shellcode),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE
            )
            if not addr:
                err = ctypes.get_last_error()
                self.logger.error(f"VirtualAllocEx failed (error={err})")
                return False
            
            self.logger.debug(f"Allocated memory at 0x{addr:016X}")
            
            # Step 2: Write shellcode
            buf = ctypes.create_string_buffer(shellcode)
            written = ctypes.c_size_t(0)
            result = self.kernel32.WriteProcessMemory(
                handle, addr, buf, len(shellcode), ctypes.byref(written)
            )
            if not result:
                err = ctypes.get_last_error()
                self.logger.error(f"WriteProcessMemory failed (error={err})")
                return False
            
            self.logger.debug(f"Wrote {written.value} bytes")
            
            # Step 3: Create remote thread
            thread_id = ctypes.wintypes.DWORD(0)
            thread_handle = self.kernel32.CreateRemoteThread(
                handle, None, 0, addr, None, 0, ctypes.byref(thread_id)
            )
            if not thread_handle:
                err = ctypes.get_last_error()
                self.logger.error(f"CreateRemoteThread failed (error={err})")
                return False
            
            self.logger.success(f"Remote thread created (TID={thread_id.value})")
            
            # Wait for thread to complete (with timeout)
            self.kernel32.WaitForSingleObject(thread_handle, 5000)  # 5 sec timeout
            self.kernel32.CloseHandle(thread_handle)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Injection failed: {e}")
            return False

    def inject_dll(self, dll_path):
        """
        Inject a DLL into the target process.
        
        Uses LoadLibraryA as the thread start routine, passing
        the DLL path as the parameter.
        
        Args:
            dll_path: Full path to the DLL file
        
        Returns:
            True if injection succeeded
        """
        if not self.kernel32:
            self.logger.error("Windows API not available")
            return False
        
        handle = self.proc_info._handle
        if not handle:
            self.logger.error("Not attached to process")
            return False
        
        self.logger.info(f"Injecting DLL: {dll_path}")
        
        try:
            # Get LoadLibraryA address
            kernel32_handle = self.kernel32.GetModuleHandleW("kernel32.dll")
            load_library = self.kernel32.GetProcAddress(kernel32_handle, b"LoadLibraryA")
            
            if not load_library:
                self.logger.error("Could not find LoadLibraryA")
                return False
            
            # Allocate memory for DLL path string
            MEM_COMMIT = 0x1000
            MEM_RESERVE = 0x2000
            PAGE_READWRITE = 0x04
            
            path_bytes = dll_path.encode("ascii") + b"\x00"
            addr = self.kernel32.VirtualAllocEx(
                handle, 0, len(path_bytes),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE
            )
            if not addr:
                self.logger.error("VirtualAllocEx failed for DLL path")
                return False
            
            # Write DLL path
            buf = ctypes.create_string_buffer(path_bytes)
            written = ctypes.c_size_t(0)
            self.kernel32.WriteProcessMemory(
                handle, addr, buf, len(path_bytes), ctypes.byref(written)
            )
            
            # Create thread with LoadLibraryA(addr) as start routine
            thread_id = ctypes.wintypes.DWORD(0)
            thread_handle = self.kernel32.CreateRemoteThread(
                handle, None, 0, load_library, addr, 0, ctypes.byref(thread_id)
            )
            if not thread_handle:
                self.logger.error("CreateRemoteThread failed for DLL injection")
                return False
            
            self.logger.success(f"DLL injection thread created (TID={thread_id.value})")
            self.kernel32.WaitForSingleObject(thread_handle, 10000)
            self.kernel32.CloseHandle(thread_handle)
            
            return True
            
        except Exception as e:
            self.logger.error(f"DLL injection failed: {e}")
            return False

    def inject_file(self, shellcode_path):
        """Load shellcode from file and inject it."""
        try:
            with open(shellcode_path, "rb") as f:
                shellcode = f.read()
            return self.inject_shellcode(shellcode)
        except FileNotFoundError:
            self.logger.error(f"File not found: {shellcode_path}")
            return False
