"""
memscan/scanner/process.py — Process management and attachment.

Handles listing processes, finding them by name/PID, attaching via
ptrace (Linux) or OpenProcess (Windows), and detecting architecture.
"""

import os
import sys
import platform
import ctypes
import ctypes.util
import psutil
from enum import Enum


class Architecture(Enum):
    """Detected process architecture."""
    X86 = 32
    X64 = 64
    UNKNOWN = 0


class ProcessInfo:
    """Container for process metadata."""
    def __init__(self, pid, name, arch=Architecture.UNKNOWN):
        self.pid = pid
        self.name = name
        self.arch = arch
        self._attached = False
        self._handle = None

    def __repr__(self):
        return f"ProcessInfo(pid={self.pid}, name='{self.name}', arch={self.arch.value}-bit)"


class ProcessManager:
    """
    Manages process discovery, attachment, and architecture detection.
    
    Works on Linux (via /proc and ptrace) and Windows (via psutil and OpenProcess).
    """

    def __init__(self, logger):
        """
        Args:
            logger: Logger instance for output
        """
        self.logger = logger
        self.os_type = platform.system().lower()
        self._libc = None
        self._load_libc()

    def _load_libc(self):
        """Load libc for ptrace on Linux."""
        if self.os_type == "linux":
            try:
                self._libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
                # ptrace constants
                self.PTRACE_ATTACH = 16 if ctypes.sizeof(ctypes.c_void_p) == 8 else 0
                self.PTRACE_DETACH = 17 if ctypes.sizeof(ctypes.c_void_p) == 8 else 1
                self.PTRACEME = 0
            except Exception as e:
                self.logger.warning(f"Could not load libc for ptrace: {e}")

    def list_processes(self, name_filter=None):
        """
        List running processes, optionally filtered by name.
        
        Args:
            name_filter: If set, only return processes whose name contains this string
        
        Returns:
            list of ProcessInfo
        """
        results = []
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                info = proc.info
                pid = info["pid"]
                name = info["name"] or "unknown"
                
                if name_filter and name_filter.lower() not in name.lower():
                    continue
                
                arch = self._detect_arch(pid)
                results.append(ProcessInfo(pid, name, arch))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return results

    def find_process(self, identifier):
        """
        Find a process by PID (int) or name (string).
        
        Args:
            identifier: int PID or string name
        
        Returns:
            ProcessInfo or None
        """
        if isinstance(identifier, int) or (isinstance(identifier, str) and identifier.isdigit()):
            pid = int(identifier)
            try:
                proc = psutil.Process(pid)
                arch = self._detect_arch(pid)
                return ProcessInfo(pid, proc.name(), arch)
            except psutil.NoSuchProcess:
                self.logger.error(
                    f"Process {pid} not found. "
                    "Use 'memscan list' to see running processes."
                )
                return None
            except psutil.AccessDenied:
                self.logger.error(
                    f"Access denied to PID {pid}. Run with sudo for process memory access."
                )
                # Return what we can
                return ProcessInfo(pid, "unknown (access denied)")
        else:
            # Search by name
            name = str(identifier)
            matches = self.list_processes(name_filter=name)
            if not matches:
                self.logger.error(f"No process found matching '{name}'")
                return None
            if len(matches) > 1:
                self.logger.info(f"Multiple matches for '{name}', using first:")
                for m in matches[:5]:
                    self.logger.info(f"  PID {m.pid}: {m.name} ({m.arch.value}-bit)")
                if len(matches) > 5:
                    self.logger.info(f"  ... and {len(matches) - 5} more")
            return matches[0]

    def attach(self, proc_info):
        """
        Attach to a process for memory operations.
        
        On Linux: uses ptrace(PTRACE_ATTACH) and waits for the process to stop.
        On Windows: uses OpenProcess with PROCESS_ALL_ACCESS.
        
        Args:
            proc_info: ProcessInfo object
        
        Returns:
            True if attached successfully, False otherwise
        """
        if proc_info._attached:
            self.logger.debug(f"Already attached to PID {proc_info.pid}")
            return True

        try:
            if self.os_type == "linux":
                return self._attach_linux(proc_info)
            elif self.os_type == "windows":
                return self._attach_windows(proc_info)
            else:
                self.logger.error(f"Unsupported OS: {self.os_type}")
                return False
        except Exception as e:
            self.logger.error(f"Failed to attach to PID {proc_info.pid}: {e}")
            if "Operation not permitted" in str(e) or "errno 1" in str(e):
                self.logger.error("Try running as root: sudo memscan ...")
            return False

    def detach(self, proc_info):
        """
        Detach from a process.
        
        Args:
            proc_info: ProcessInfo object
        """
        if not proc_info._attached:
            return

        try:
            if self.os_type == "linux":
                self._detach_linux(proc_info)
            elif self.os_type == "windows":
                self._detach_windows(proc_info)
            proc_info._attached = False
            self.logger.debug(f"Detached from PID {proc_info.pid}")
        except Exception as e:
            self.logger.warning(f"Error detaching from PID {proc_info.pid}: {e}")

    def _attach_linux(self, proc_info):
        """Attach to a Linux process using ptrace."""
        if not self._libc:
            self.logger.error("libc not loaded — ptrace unavailable")
            return False

        pid = proc_info.pid
        result = self._libc.ptrace(self.PTRACE_ATTACH, pid, 0, 0)
        if result != 0:
            errno = ctypes.get_errno()
            if errno == 1:  # EPERM
                self.logger.error(f"Permission denied attaching to PID {pid}. Run as root.")
            elif errno == 3:  # ESRCH
                self.logger.error(f"Process {pid} does not exist.")
            else:
                self.logger.error(f"ptrace attach failed for PID {pid} (errno={errno})")
            return False

        # Wait for the process to stop
        import signal
        try:
            _, status = os.waitpid(pid, os.WUNTRACED)
            if os.WIFSTOPPED(status):
                proc_info._attached = True
                self.logger.debug(f"Attached to PID {pid} (stopped with signal {os.WSTOPSIG(status)})")
                return True
            else:
                self.logger.error(f"Process {pid} did not stop as expected")
                return False
        except ChildProcessError:
            # If we're not the parent, waitpid may fail — but ptrace attach worked
            proc_info._attached = True
            self.logger.debug(f"Attached to PID {pid} (waitpid unavailable, assuming success)")
            return True

    def _detach_linux(self, proc_info):
        """Detach from a Linux process using ptrace."""
        pid = proc_info.pid
        # Send SIGCONT to resume after detach
        result = self._libc.ptrace(self.PTRACE_DETACH, pid, 0, 0)
        if result != 0:
            self.logger.warning(f"ptrace detach returned non-zero for PID {pid}")

    def _attach_windows(self, proc_info):
        """Attach to a Windows process using OpenProcess."""
        try:
            import ctypes.wintypes
            
            PROCESS_ALL_ACCESS = 0x1F0FFF
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, proc_info.pid)
            if not handle:
                err = ctypes.get_last_error()
                if err == 5:  # ERROR_ACCESS_DENIED
                    self.logger.error(f"Access denied to PID {proc_info.pid}. Run as Administrator.")
                else:
                    self.logger.error(f"OpenProcess failed for PID {proc_info.pid} (error={err})")
                return False
            
            proc_info._handle = handle
            proc_info._attached = True
            self.logger.debug(f"Opened handle to PID {proc_info.pid}")
            return True
        except AttributeError:
            self.logger.error("Windows API not available (not on Windows)")
            return False

    def _detach_windows(self, proc_info):
        """Close handle to a Windows process."""
        if proc_info._handle:
            try:
                import ctypes.wintypes
                kernel32 = ctypes.windll.kernel32
                kernel32.CloseHandle(proc_info._handle)
                proc_info._handle = None
            except Exception:
                pass

    def _detect_arch(self, pid):
        """
        Detect whether a process is 32-bit or 64-bit.
        
        On Linux: reads /proc/<pid>/exe and checks ELF header, or
                 checks /proc/<pid>/maps for [vsyscall] (64-bit indicator).
        On Windows: uses IsWow64Process.
        
        Returns:
            Architecture enum
        """
        try:
            if self.os_type == "linux":
                return self._detect_arch_linux(pid)
            elif self.os_type == "windows":
                return self._detect_arch_windows(pid)
        except Exception:
            pass
        return Architecture.UNKNOWN

    def _detect_arch_linux(self, pid):
        """Detect architecture on Linux via ELF header."""
        try:
            exe_path = f"/proc/{pid}/exe"
            if not os.path.exists(exe_path):
                return Architecture.UNKNOWN
            
            # Read ELF header
            real_path = os.readlink(exe_path)
            with open(real_path, "rb") as f:
                magic = f.read(5)
                if magic[:4] != b"\x7fELF":
                    return Architecture.UNKNOWN
                # Byte 4: 1 = 32-bit, 2 = 64-bit
                ei_class = magic[4]
                if ei_class == 2:
                    return Architecture.X64
                elif ei_class == 1:
                    return Architecture.X86
        except (OSError, PermissionError):
            pass
        return Architecture.UNKNOWN

    def _detect_arch_windows(self, pid):
        """Detect architecture on Windows using IsWow64Process."""
        try:
            import ctypes.wintypes
            kernel32 = ctypes.windll.kernel32
            
            PROCESS_QUERY_INFORMATION = 0x0400
            handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
            if not handle:
                return Architecture.UNKNOWN
            
            is_wow64 = ctypes.wintypes.BOOL()
            result = kernel32.IsWow64Process(handle, ctypes.byref(is_wow64))
            kernel32.CloseHandle(handle)
            
            if result:
                if is_wow64.value:
                    # Running under WOW64 = 32-bit on 64-bit OS
                    return Architecture.X86
                else:
                    # Could be 64-bit native or 32-bit on 32-bit OS
                    if ctypes.sizeof(ctypes.c_void_p) == 8:
                        return Architecture.X64
                    else:
                        return Architecture.X86
        except Exception:
            pass
        return Architecture.UNKNOWN

    def get_modules(self, proc_info):
        """
        Get loaded modules/libraries for a process.
        
        Args:
            proc_info: ProcessInfo object
        
        Returns:
            list of dicts with 'name', 'base', 'size' keys
        """
        modules = []
        try:
            proc = psutil.Process(proc_info.pid)
            
            if self.os_type == "linux":
                # Parse /proc/<pid>/maps
                maps_path = f"/proc/{proc_info.pid}/maps"
                if os.path.exists(maps_path):
                    with open(maps_path, "r") as f:
                        seen = set()
                        for line in f:
                            parts = line.strip().split()
                            if len(parts) >= 6:
                                path = parts[5]
                                if path in seen or path.startswith("["):
                                    continue
                                seen.add(path)
                                addr_range = parts[0].split("-")
                                base = int(addr_range[0], 16)
                                end = int(addr_range[1], 16)
                                name = os.path.basename(path)
                                modules.append({
                                    "name": name,
                                    "path": path,
                                    "base": base,
                                    "size": end - base
                                })
            elif self.os_type == "windows":
                # Windows module enumeration via psutil or WMI
                # psutil on Windows can get memory_maps
                try:
                    for mmap in proc.memory_maps():
                        modules.append({
                            "name": os.path.basename(mmap.path),
                            "path": mmap.path,
                            "base": int(mmap.addr.split("-")[0], 16),
                            "size": 0  # psutil doesn't give size directly
                        })
                except (psutil.AccessDenied, AttributeError):
                    pass
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            self.logger.error(f"Cannot enumerate modules for PID {proc_info.pid}: {e}")
        
        return modules
