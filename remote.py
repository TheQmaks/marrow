"""Cross-process memory reader for Windows x64.

Resolves exported symbols in a target process's loaded module (by default
jvm.dll) without injecting anything — we open the process with
PROCESS_VM_READ and parse the PE export table via ReadProcessMemory.

Used by VMMeta.from_pid() to attach to a running JVM.
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import struct

# --- Win32 bindings -------------------------------------------------------

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40

# exported so vm_meta & callers can construct calls without re-importing.


_k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
_k32.OpenProcess.restype = wt.HANDLE
_k32.CloseHandle.argtypes = [wt.HANDLE]
_k32.CloseHandle.restype = wt.BOOL
_k32.ReadProcessMemory.argtypes = [
    wt.HANDLE, wt.LPCVOID, wt.LPVOID, ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
_k32.ReadProcessMemory.restype = wt.BOOL
_k32.WriteProcessMemory.argtypes = [
    wt.HANDLE, wt.LPVOID, wt.LPCVOID, ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
_k32.WriteProcessMemory.restype = wt.BOOL
_k32.VirtualProtectEx.argtypes = [
    wt.HANDLE, wt.LPVOID, ctypes.c_size_t, wt.DWORD, ctypes.POINTER(wt.DWORD),
]
_k32.VirtualProtectEx.restype = wt.BOOL
_k32.VirtualAllocEx.argtypes = [
    wt.HANDLE, wt.LPVOID, ctypes.c_size_t, wt.DWORD, wt.DWORD,
]
_k32.VirtualAllocEx.restype = wt.LPVOID
_k32.VirtualFreeEx.argtypes = [wt.HANDLE, wt.LPVOID, ctypes.c_size_t, wt.DWORD]
_k32.VirtualFreeEx.restype = wt.BOOL


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       ctypes.c_void_p),
        ("AllocationBase",    ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("__alignment1",      wt.DWORD),
        ("RegionSize",        ctypes.c_size_t),
        ("State",             wt.DWORD),
        ("Protect",           wt.DWORD),
        ("Type",              wt.DWORD),
        ("__alignment2",      wt.DWORD),
    ]


_k32.VirtualQueryEx.argtypes = [
    wt.HANDLE, wt.LPCVOID,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t,
]
_k32.VirtualQueryEx.restype = ctypes.c_size_t

MEM_COMMIT_STATE = 0x1000

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
_k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
_k32.CreateToolhelp32Snapshot.restype = wt.HANDLE


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize",         wt.DWORD),
        ("th32ModuleID",   wt.DWORD),
        ("th32ProcessID",  wt.DWORD),
        ("GlblcntUsage",   wt.DWORD),
        ("ProccntUsage",   wt.DWORD),
        ("modBaseAddr",    ctypes.c_void_p),
        ("modBaseSize",    wt.DWORD),
        ("hModule",        wt.HMODULE),
        ("szModule",       wt.WCHAR * 256),
        ("szExePath",      wt.WCHAR * 260),
    ]


_k32.Module32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
_k32.Module32FirstW.restype = wt.BOOL
_k32.Module32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
_k32.Module32NextW.restype = wt.BOOL


INVALID_HANDLE_VALUE = wt.HANDLE(-1).value


# --- helpers --------------------------------------------------------------

def _oserr(fn: str) -> OSError:
    err = ctypes.get_last_error()
    return OSError(err, f"{fn}: {ctypes.WinError(err)}")


def find_module_base(pid: int, name_ci: str) -> tuple[int, int, str]:
    """Return (base_address, size, full_path) for the named module in pid.

    name_ci matches case-insensitively against MODULEENTRY32W.szModule.
    """
    flags = TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32
    snap = _k32.CreateToolhelp32Snapshot(flags, pid)
    if snap == INVALID_HANDLE_VALUE:
        raise _oserr(f"CreateToolhelp32Snapshot(pid={pid})")
    try:
        entry = MODULEENTRY32W()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
        if not _k32.Module32FirstW(snap, ctypes.byref(entry)):
            raise _oserr("Module32FirstW")
        want = name_ci.lower()
        while True:
            if entry.szModule.lower() == want:
                return (entry.modBaseAddr or 0,
                        entry.modBaseSize,
                        entry.szExePath)
            if not _k32.Module32NextW(snap, ctypes.byref(entry)):
                break
        raise LookupError(f"module {name_ci!r} not found in pid {pid}")
    finally:
        _k32.CloseHandle(snap)


# --- PE export table parser ----------------------------------------------

def _parse_exports(read_raw, base: int) -> dict[str, int]:
    """Parse a PE64 image loaded at `base` and return {name: absolute_addr}.

    read_raw(addr, size) -> bytes. Only x64 images are supported.
    """
    dos = read_raw(base, 64)
    if dos[:2] != b"MZ":
        raise ValueError(f"not a PE image at {base:#x}: magic={dos[:2]!r}")
    e_lfanew = struct.unpack_from("<i", dos, 0x3C)[0]

    nt = read_raw(base + e_lfanew, 24 + 240)  # sig + FileHeader + OptHeader64
    if nt[:4] != b"PE\x00\x00":
        raise ValueError("bad NT signature")
    # OptionalHeader starts at offset 24 within `nt`.
    opt = nt[24:]
    magic = struct.unpack_from("<H", opt, 0)[0]
    if magic != 0x20B:
        raise ValueError(f"not PE32+ (x64); OptionalHeader magic={magic:#x}")
    # DataDirectory array starts at offset 112 in OptionalHeader64,
    # entry 0 is Export Directory (RVA, Size).
    exp_rva, exp_size = struct.unpack_from("<II", opt, 112)
    if exp_rva == 0 or exp_size == 0:
        return {}
    exp_start = base + exp_rva
    exp_end = exp_start + exp_size  # for forwarded-export detection

    exp = read_raw(exp_start, 40)
    (_chars, _ts, _maj, _min, _name_rva, _ordinal_base,
     n_funcs, n_names,
     addr_functions_rva, addr_names_rva, addr_ordinals_rva) = \
        struct.unpack_from("<IIHHIIIIIII", exp, 0)

    # Bulk-read the three RVA arrays — they're small.
    funcs = read_raw(base + addr_functions_rva, n_funcs * 4)
    names = read_raw(base + addr_names_rva,     n_names * 4)
    ords_ = read_raw(base + addr_ordinals_rva,  n_names * 2)

    # Read each name string (chunked). Sorted per PE spec but we just
    # build a dict — N is typically ~1k, cost is negligible.
    out: dict[str, int] = {}
    for i in range(n_names):
        name_rva = struct.unpack_from("<I", names, i * 4)[0]
        name_str = _read_cstring_chunked(read_raw, base + name_rva, cap=256)
        ordinal = struct.unpack_from("<H", ords_, i * 2)[0]
        func_rva = struct.unpack_from("<I", funcs, ordinal * 4)[0]
        func_abs = base + func_rva
        if exp_start <= func_abs < exp_end:
            # Forwarded export — skip (none of ours are forwarded).
            continue
        out[name_str] = func_abs
    return out


def _read_cstring_chunked(read_raw, addr: int, cap: int = 4096) -> str:
    buf = bytearray()
    remaining = cap
    while remaining > 0:
        chunk = min(64, remaining)
        try:
            data = read_raw(addr + len(buf), chunk)
        except OSError:
            break
        nul = data.find(b"\x00")
        if nul >= 0:
            buf.extend(data[:nul])
            break
        buf.extend(data)
        remaining -= chunk
    return buf.decode("utf-8", errors="replace")


# --- RemoteReader ---------------------------------------------------------

class RemoteReader:
    """Memory reader for a target Windows process.

    Resolves symbols via PE export table parsing and reads memory via
    ReadProcessMemory. Compatible with VMMeta — provides the same
    read()/symbol()/cstring() surface as LocalReader.
    """

    def __init__(self, pid: int, module_name: str = "jvm.dll",
                 writable: bool = True):
        self.pid = pid
        self.module_name = module_name
        self.writable = writable
        access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
        if writable:
            access |= PROCESS_VM_WRITE | PROCESS_VM_OPERATION
        self._h = _k32.OpenProcess(access, False, pid)
        if not self._h:
            raise _oserr(f"OpenProcess(pid={pid})")
        self.module_base, self.module_size, self.module_path = \
            find_module_base(pid, module_name)
        self._exports = _parse_exports(self._read_raw, self.module_base)

    # Low-level raw read used by the PE parser. Raises OSError on any
    # short/failed read so the caller can decide how to recover.
    def _read_raw(self, addr: int, size: int) -> bytes:
        buf = (ctypes.c_char * size)()
        read = ctypes.c_size_t(0)
        ok = _k32.ReadProcessMemory(self._h, addr, buf, size, ctypes.byref(read))
        if not ok or read.value != size:
            raise _oserr(f"ReadProcessMemory({addr:#x}, {size})")
        return bytes(buf)

    # --- interface shared with LocalReader --------------------------------

    def read(self, addr: int, size: int) -> bytes:
        return self._read_raw(addr, size)

    def symbol(self, name: str) -> int:
        try:
            return self._exports[name]
        except KeyError:
            raise KeyError(f"export {name!r} not in {self.module_name} "
                           f"of pid {self.pid}") from None

    def opt_symbol(self, name: str) -> int | None:
        return self._exports.get(name)

    def cstring(self, addr: int) -> str:
        return _read_cstring_chunked(self._read_raw, addr)

    # --- write (optional — available when constructor was given writable=True)

    def write(self, addr: int, data: bytes) -> None:
        """Write bytes into the target process. Attempts to bypass page
        protection once if the initial WPM fails."""
        if not self.writable:
            raise PermissionError("RemoteReader opened without write access")
        n = len(data)
        written = ctypes.c_size_t(0)
        ok = _k32.WriteProcessMemory(self._h, addr, data, n, ctypes.byref(written))
        if ok and written.value == n:
            return
        # Retry after flipping the covering page(s) to PAGE_READWRITE.
        old = wt.DWORD(0)
        # Covers a single 4 KiB page from addr onward; enlarge if needed.
        page_size = 0x1000
        region_len = n + (addr & (page_size - 1))
        if not _k32.VirtualProtectEx(self._h, addr, region_len,
                                     PAGE_READWRITE, ctypes.byref(old)):
            raise _oserr(f"VirtualProtectEx({addr:#x}, {region_len})")
        try:
            ok = _k32.WriteProcessMemory(
                self._h, addr, data, n, ctypes.byref(written))
            if not ok or written.value != n:
                raise _oserr(f"WriteProcessMemory({addr:#x}, {n})")
        finally:
            _k32.VirtualProtectEx(self._h, addr, region_len,
                                  old.value, ctypes.byref(old))

    def alloc(self, size: int, executable: bool = False) -> int:
        """Allocate committed memory in the target. Used for hook
        trampolines (executable=True) and shared counters (False)."""
        if not self.writable:
            raise PermissionError("RemoteReader opened without write access")
        prot = PAGE_EXECUTE_READWRITE if executable else PAGE_READWRITE
        addr = _k32.VirtualAllocEx(self._h, None, size,
                                    MEM_COMMIT | MEM_RESERVE, prot)
        if not addr:
            raise _oserr(f"VirtualAllocEx({size}, exec={executable})")
        return addr

    def free(self, addr: int) -> None:
        if addr:
            _k32.VirtualFreeEx(self._h, addr, 0, MEM_RELEASE)

    def enumerate_regions(self, min_addr: int = 0,
                          max_addr: int = 0x0000_7FFF_FFFF_FFFF,
                          writable_only: bool = True):
        """Walk every committed memory region in the target, yielding
        (base, size, protect). `VirtualQueryEx` moves forward one region
        at a time; the user-mode address range on Windows x64 caps at
        0x7FFF_FFFF_FFFF."""
        mbi = MEMORY_BASIC_INFORMATION()
        mbi_sz = ctypes.sizeof(MEMORY_BASIC_INFORMATION)
        addr = min_addr
        while addr < max_addr:
            ret = _k32.VirtualQueryEx(
                self._h, addr, ctypes.byref(mbi), mbi_sz)
            if ret == 0:
                break
            base = mbi.BaseAddress or 0
            size = mbi.RegionSize
            if mbi.State == MEM_COMMIT_STATE:
                prot = mbi.Protect & 0xFF  # PAGE_* low byte
                # Writable protections: 0x04 RW, 0x40 ERW, 0x02 RO, 0x20 ER.
                if not writable_only or prot in (0x04, 0x40):
                    yield (base, size, prot)
            addr = base + size

    def close(self) -> None:
        if self._h:
            _k32.CloseHandle(self._h)
            self._h = 0

    def __enter__(self):  return self
    def __exit__(self, *_exc): self.close()

    def __repr__(self) -> str:
        return (f"RemoteReader(pid={self.pid}, "
                f"{self.module_name}@{self.module_base:#x}, "
                f"exports={len(self._exports)})")
