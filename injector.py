"""DLL injection + shared-control-block helper.

Loads an arbitrary DLL into a target process via the classic
`CreateRemoteThread(LoadLibraryA)` trick and exposes the shared memory
region that the injected DLL coordinates on.

Scope: just enough plumbing for the hardware field watcher demo. The
shared block layout mirrors `watcher.cpp::ControlBlock`:

    offset  size  field
    ------  ----  -------------------------
      0      8    watched_addr   (uintptr_t)
      8      8    write_count    (uint64_t)
     16      8    last_fault_rip
     24      8    last_fault_addr
     32      4    installed      (int)
     36      4    _pad
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import mmap
import struct

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)

PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04
PAGE_READONLY = 0x02
INFINITE = 0xFFFFFFFF
SHARED_NAME = "Local\\jvm-probe-watch-v1"
CONTROL_BLOCK_SIZE = 56  # matches watcher.cpp::ControlBlock layout

_k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
_k32.OpenProcess.restype = wt.HANDLE
_k32.CloseHandle.argtypes = [wt.HANDLE]
_k32.CloseHandle.restype = wt.BOOL
_k32.VirtualAllocEx.argtypes = [
    wt.HANDLE, wt.LPVOID, ctypes.c_size_t, wt.DWORD, wt.DWORD]
_k32.VirtualAllocEx.restype = wt.LPVOID
_k32.VirtualFreeEx.argtypes = [wt.HANDLE, wt.LPVOID, ctypes.c_size_t, wt.DWORD]
_k32.VirtualFreeEx.restype = wt.BOOL
_k32.WriteProcessMemory.argtypes = [
    wt.HANDLE, wt.LPVOID, wt.LPCVOID, ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t)]
_k32.WriteProcessMemory.restype = wt.BOOL
_k32.CreateRemoteThread.argtypes = [
    wt.HANDLE, wt.LPVOID, ctypes.c_size_t, wt.LPVOID, wt.LPVOID,
    wt.DWORD, ctypes.POINTER(wt.DWORD)]
_k32.CreateRemoteThread.restype = wt.HANDLE
_k32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
_k32.WaitForSingleObject.restype = wt.DWORD
_k32.GetModuleHandleA.argtypes = [wt.LPCSTR]
_k32.GetModuleHandleA.restype = wt.HMODULE
_k32.GetProcAddress.argtypes = [wt.HMODULE, wt.LPCSTR]
_k32.GetProcAddress.restype = ctypes.c_void_p
_k32.VirtualProtectEx.argtypes = [
    wt.HANDLE, wt.LPVOID, ctypes.c_size_t, wt.DWORD,
    ctypes.POINTER(wt.DWORD)]
_k32.VirtualProtectEx.restype = wt.BOOL


def _oserr(fn: str) -> OSError:
    err = ctypes.get_last_error()
    return OSError(err, f"{fn}: {ctypes.WinError(err)}")


class SharedControlBlock:
    """Named shared-memory region used to pass config to the watcher DLL
    and read back its hit counter.

    Lifetime: hold the Python instance alive until uninstall. Creating a
    second instance with the same name returns a handle to the same
    underlying region."""

    def __init__(self):
        # mmap with a tagged name creates/opens a system-wide mapping
        # (equivalent to CreateFileMapping backed by pagefile).
        self._mm = mmap.mmap(-1, CONTROL_BLOCK_SIZE, tagname=SHARED_NAME)
        self._addr = ctypes.addressof(ctypes.c_char.from_buffer(self._mm))
        self.clear()

    @property
    def addr(self) -> int:
        """Address of the control block in OUR process (not target's)."""
        return self._addr

    def clear(self) -> None:
        ctypes.memset(self._addr, 0, CONTROL_BLOCK_SIZE)

    def set_watched(self, addr: int) -> None:
        struct.pack_into("<Q", self._mm, 0, addr & 0xFFFFFFFFFFFFFFFF)

    def get_watched(self) -> int:
        return struct.unpack_from("<Q", self._mm, 0)[0]

    def get_count(self) -> int:
        return struct.unpack_from("<Q", self._mm, 8)[0]

    def get_last_fault_rip(self) -> int:
        return struct.unpack_from("<Q", self._mm, 16)[0]

    def get_last_fault_addr(self) -> int:
        return struct.unpack_from("<Q", self._mm, 24)[0]

    def is_installed(self) -> bool:
        return struct.unpack_from("<i", self._mm, 32)[0] == 1

    def close(self) -> None:
        self._mm.close()


def inject_dll(pid: int, dll_path: str, timeout_ms: int = 5000) -> int:
    """Load `dll_path` into the target process. Returns the thread exit
    code, which equals the HMODULE of the loaded library (or 0 on
    failure) thanks to LoadLibraryA's return type fitting in a DWORD
    thread-exit-code on x64."""
    hproc = _k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not hproc:
        raise _oserr(f"OpenProcess({pid})")
    try:
        path_bytes = (dll_path + "\0").encode("ascii")
        remote = _k32.VirtualAllocEx(
            hproc, None, len(path_bytes),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if not remote:
            raise _oserr("VirtualAllocEx(DLL path)")
        try:
            written = ctypes.c_size_t(0)
            if not _k32.WriteProcessMemory(
                    hproc, remote, path_bytes, len(path_bytes),
                    ctypes.byref(written)):
                raise _oserr("WriteProcessMemory(DLL path)")
            k32_local = _k32.GetModuleHandleA(b"kernel32.dll")
            load_lib = _k32.GetProcAddress(k32_local, b"LoadLibraryA")
            if not load_lib:
                raise _oserr("GetProcAddress(LoadLibraryA)")
            tid = wt.DWORD(0)
            hthread = _k32.CreateRemoteThread(
                hproc, None, 0, load_lib, remote, 0, ctypes.byref(tid))
            if not hthread:
                raise _oserr("CreateRemoteThread")
            try:
                if _k32.WaitForSingleObject(hthread, timeout_ms) != 0:
                    raise TimeoutError("injected thread did not finish in time")
                exit_code = wt.DWORD(0)
                ctypes.windll.kernel32.GetExitCodeThread(
                    hthread, ctypes.byref(exit_code))
                return exit_code.value
            finally:
                _k32.CloseHandle(hthread)
        finally:
            _k32.VirtualFreeEx(hproc, remote, 0, MEM_RELEASE)
    finally:
        _k32.CloseHandle(hproc)


# --- Hardware debug-register watchpoints (DR0..DR3) --------------------------

# CONTEXT structure on AMD64 — we need DR fields at their fixed offsets.
# Total size is 1232 bytes; pad beyond DR7 with a tail byte array.
_CONTEXT_AMD64_FLAG = 0x00100000
_CONTEXT_DEBUG_REGISTERS_FLAG = _CONTEXT_AMD64_FLAG | 0x10


class CONTEXT64(ctypes.Structure):
    _pack_ = 16  # keeps Xmm-tail alignment stable
    _fields_ = [
        ("P1Home", ctypes.c_uint64), ("P2Home", ctypes.c_uint64),
        ("P3Home", ctypes.c_uint64), ("P4Home", ctypes.c_uint64),
        ("P5Home", ctypes.c_uint64), ("P6Home", ctypes.c_uint64),
        ("ContextFlags", ctypes.c_uint32), ("MxCsr", ctypes.c_uint32),
        ("SegCs", ctypes.c_uint16), ("SegDs", ctypes.c_uint16),
        ("SegEs", ctypes.c_uint16), ("SegFs", ctypes.c_uint16),
        ("SegGs", ctypes.c_uint16), ("SegSs", ctypes.c_uint16),
        ("EFlags", ctypes.c_uint32),
        ("Dr0", ctypes.c_uint64), ("Dr1", ctypes.c_uint64),
        ("Dr2", ctypes.c_uint64), ("Dr3", ctypes.c_uint64),
        ("Dr6", ctypes.c_uint64), ("Dr7", ctypes.c_uint64),
        ("Tail", ctypes.c_ubyte * (1232 - 120)),
    ]


THREAD_GET_CONTEXT = 0x0008
THREAD_SET_CONTEXT = 0x0010
THREAD_SUSPEND_RESUME = 0x0002
THREAD_DR_ACCESS = (THREAD_GET_CONTEXT | THREAD_SET_CONTEXT
                    | THREAD_SUSPEND_RESUME)

TH32CS_SNAPTHREAD = 0x00000004


class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ThreadID", wt.DWORD),
        ("th32OwnerProcessID", wt.DWORD),
        ("tpBasePri", ctypes.c_long),
        ("tpDeltaPri", ctypes.c_long),
        ("dwFlags", wt.DWORD),
    ]


_k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
_k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
_k32.Thread32First.argtypes = [wt.HANDLE, ctypes.POINTER(THREADENTRY32)]
_k32.Thread32First.restype = wt.BOOL
_k32.Thread32Next.argtypes = [wt.HANDLE, ctypes.POINTER(THREADENTRY32)]
_k32.Thread32Next.restype = wt.BOOL
_k32.OpenThread.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
_k32.OpenThread.restype = wt.HANDLE
_k32.SuspendThread.argtypes = [wt.HANDLE]
_k32.SuspendThread.restype = wt.DWORD
_k32.ResumeThread.argtypes = [wt.HANDLE]
_k32.ResumeThread.restype = wt.DWORD
_k32.GetThreadContext.argtypes = [wt.HANDLE, ctypes.POINTER(CONTEXT64)]
_k32.GetThreadContext.restype = wt.BOOL
_k32.SetThreadContext.argtypes = [wt.HANDLE, ctypes.POINTER(CONTEXT64)]
_k32.SetThreadContext.restype = wt.BOOL


def _enumerate_thread_ids(pid: int) -> list[int]:
    snap = _k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if snap == -1 or not snap:
        raise _oserr("CreateToolhelp32Snapshot(THREAD)")
    try:
        entry = THREADENTRY32()
        entry.dwSize = ctypes.sizeof(THREADENTRY32)
        tids: list[int] = []
        if not _k32.Thread32First(snap, ctypes.byref(entry)):
            return []
        while True:
            if entry.th32OwnerProcessID == pid:
                tids.append(entry.th32ThreadID)
            if not _k32.Thread32Next(snap, ctypes.byref(entry)):
                break
        return tids
    finally:
        _k32.CloseHandle(snap)


def _dr7_for_slot(slot: int, length: int, write_only: bool) -> int:
    """Encode DR7 bits for slot 0..3 watching `length` bytes.

    length: 1, 2, 4, 8 -> LEN code 00, 01, 11, 10
    write_only: True -> RW=01, False (R/W) -> RW=11
    """
    len_code = {1: 0, 2: 1, 4: 3, 8: 2}[length]
    rw_code = 1 if write_only else 3
    # L<slot> bit at position 2*slot; RW<slot> at 16+4*slot; LEN<slot> at 18+4*slot.
    return (1 << (slot * 2)) \
           | (rw_code << (16 + slot * 4)) \
           | (len_code << (18 + slot * 4))


def _dr7_clear_mask(slot: int) -> int:
    return (0b11 << (slot * 2)) \
           | (0b1111 << (16 + slot * 4))


def set_hw_watchpoint(pid: int, addr: int, length: int = 4,
                      slot: int = 0, write_only: bool = True) -> int:
    """Arm DR<slot> across every thread of the target process so that a
    write to `addr` (for `length` bytes) raises EXCEPTION_SINGLE_STEP.
    The watcher DLL picks this up in its VEH and counts the hit.

    Returns number of threads successfully configured."""
    ok = 0
    dr7_bits = _dr7_for_slot(slot, length, write_only)
    for tid in _enumerate_thread_ids(pid):
        h = _k32.OpenThread(THREAD_DR_ACCESS, False, tid)
        if not h:
            continue
        try:
            _k32.SuspendThread(h)
            ctx = CONTEXT64()
            ctx.ContextFlags = _CONTEXT_DEBUG_REGISTERS_FLAG
            if not _k32.GetThreadContext(h, ctypes.byref(ctx)):
                continue
            # Install watched address in the right DR slot; OR bits into DR7.
            setattr(ctx, f"Dr{slot}", addr)
            ctx.Dr7 = (ctx.Dr7 & ~_dr7_clear_mask(slot)) | dr7_bits
            ctx.ContextFlags = _CONTEXT_DEBUG_REGISTERS_FLAG
            if _k32.SetThreadContext(h, ctypes.byref(ctx)):
                ok += 1
        finally:
            _k32.ResumeThread(h)
            _k32.CloseHandle(h)
    return ok


def clear_hw_watchpoint(pid: int, slot: int = 0) -> int:
    ok = 0
    for tid in _enumerate_thread_ids(pid):
        h = _k32.OpenThread(THREAD_DR_ACCESS, False, tid)
        if not h:
            continue
        try:
            _k32.SuspendThread(h)
            ctx = CONTEXT64()
            ctx.ContextFlags = _CONTEXT_DEBUG_REGISTERS_FLAG
            if not _k32.GetThreadContext(h, ctypes.byref(ctx)):
                continue
            setattr(ctx, f"Dr{slot}", 0)
            ctx.Dr7 &= ~_dr7_clear_mask(slot)
            ctx.ContextFlags = _CONTEXT_DEBUG_REGISTERS_FLAG
            if _k32.SetThreadContext(h, ctypes.byref(ctx)):
                ok += 1
        finally:
            _k32.ResumeThread(h)
            _k32.CloseHandle(h)
    return ok


def protect_remote_page(pid: int, addr: int,
                        readonly: bool = True) -> int:
    """Flip the page containing `addr` to PAGE_READONLY (default) or back
    to PAGE_READWRITE. Returns the previous protection value."""
    hproc = _k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not hproc:
        raise _oserr(f"OpenProcess({pid})")
    try:
        page = addr & ~0xFFF
        new_prot = PAGE_READONLY if readonly else PAGE_READWRITE
        old = wt.DWORD(0)
        if not _k32.VirtualProtectEx(
                hproc, page, 0x1000, new_prot, ctypes.byref(old)):
            raise _oserr(f"VirtualProtectEx({page:#x})")
        return old.value
    finally:
        _k32.CloseHandle(hproc)
