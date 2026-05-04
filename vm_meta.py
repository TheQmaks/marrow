"""High-level API over HotSpot's self-describing VM metadata.

Parses gHotSpotVMStructs / gHotSpotVMTypes / gHotSpotVMIntConstants /
gHotSpotVMLongConstants from any jvm.dll (JDK 8..25) and exposes a small
object model for later layers (walker, reader, writer, hooks).

Works in two modes:
    VMMeta.from_dll(path)  — load jvm.dll into our process, read locally
    VMMeta.from_pid(pid)   — attach to a running JVM, read via RPM

Example
-------
    vm = VMMeta.from_dll(r"C:\\...\\jvm.dll")
    name_f = vm.type("Klass").field("_name")  # offset=24, typeString="Symbol*"

    vm = VMMeta.from_pid(12345)               # running JVM
    head = vm.type("ClassLoaderDataGraph").static_field("_head").address
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import struct
from dataclasses import dataclass, field as _dc_field
from typing import ClassVar, Protocol

# --- kernel32 bindings for LocalReader ------------------------------------

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.LoadLibraryExW.argtypes = [wt.LPCWSTR, wt.HANDLE, wt.DWORD]
_k32.LoadLibraryExW.restype = wt.HMODULE
_k32.GetProcAddress.argtypes = [wt.HMODULE, ctypes.c_char_p]
_k32.GetProcAddress.restype = ctypes.c_void_p
_k32.FreeLibrary.argtypes = [wt.HMODULE]

_DONT_RESOLVE_DLL_REFS = 0x00000001


# --- Memory reader interface ----------------------------------------------

class Reader(Protocol):
    """Minimal surface VMMeta needs from its memory backend.

    Implementations: LocalReader (in-process jvm.dll) and RemoteReader
    (cross-process via ReadProcessMemory — see remote.py).
    """
    def read(self, addr: int, size: int) -> bytes: ...
    def symbol(self, name: str) -> int: ...
    def opt_symbol(self, name: str) -> int | None: ...
    def cstring(self, addr: int) -> str: ...
    def close(self) -> None: ...


def _write(r, addr: int, data: bytes) -> None:
    if not hasattr(r, "write"):
        raise RuntimeError("reader does not support writing "
                           "(LocalReader is read-only by design)")
    r.write(addr, data)


def _write_u32(r, addr: int, value: int) -> None:
    _write(r, addr, struct.pack("<I", value & 0xFFFFFFFF))


def _write_u64(r, addr: int, value: int) -> None:
    _write(r, addr, struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF))


def _write_i32(r, addr: int, value: int) -> None:
    _write(r, addr, struct.pack("<i", value))


class LocalReader:
    """Reader backed by LoadLibraryEx + direct dereferences."""

    def __init__(self, dll_path: str):
        self.dll_path = dll_path
        self._h = _k32.LoadLibraryExW(dll_path, None, _DONT_RESOLVE_DLL_REFS)
        if not self._h:
            raise OSError(
                f"LoadLibraryEx({dll_path}) failed: "
                f"{ctypes.WinError(ctypes.get_last_error())}"
            )

    def read(self, addr: int, size: int) -> bytes:
        return ctypes.string_at(addr, size)

    def symbol(self, name: str) -> int:
        a = _k32.GetProcAddress(self._h, name.encode("ascii"))
        if not a:
            raise KeyError(f"missing export: {name}")
        return a

    def opt_symbol(self, name: str) -> int | None:
        return _k32.GetProcAddress(self._h, name.encode("ascii")) or None

    def cstring(self, addr: int) -> str:
        return ctypes.string_at(addr).decode("utf-8", "replace") if addr else ""

    def close(self) -> None:
        if self._h:
            _k32.FreeLibrary(self._h)
            self._h = 0

    def __repr__(self) -> str:
        return f"LocalReader({self.dll_path!r})"


# --- Primitive readers (reader-agnostic) ----------------------------------

def _u64(r: Reader, addr: int) -> int:
    return struct.unpack_from("<Q", r.read(addr, 8))[0]


def _i32(r: Reader, addr: int) -> int:
    return struct.unpack_from("<i", r.read(addr, 4))[0]


def _u32(r: Reader, addr: int) -> int:
    return struct.unpack_from("<I", r.read(addr, 4))[0]


def _u16(r: Reader, addr: int) -> int:
    return struct.unpack_from("<H", r.read(addr, 2))[0]


def _size_t(r: Reader, addr: int) -> int:
    # x64 only — size_t is 8 bytes.
    return _u64(r, addr)


def _ptr(r: Reader, addr: int) -> int:
    return _u64(r, addr)


# --- FieldInfo / TypeInfo -------------------------------------------------

@dataclass(frozen=True)
class FieldInfo:
    type_name: str
    name: str
    type_string: str
    is_static: bool
    offset: int       # meaningful when is_static == False
    address: int      # meaningful when is_static == True

    def __repr__(self) -> str:
        tag = f"@{self.address:#x}" if self.is_static else f"offset={self.offset}"
        return f"Field({self.type_name}::{self.name} : {self.type_string} {tag})"


@dataclass
class TypeInfo:
    name: str
    super_name: str
    size: int
    is_oop: bool
    is_integer: bool
    is_unsigned: bool
    _fields: dict = _dc_field(default_factory=dict, repr=False)

    def field(self, name: str) -> FieldInfo:
        try:
            return self._fields[name]
        except KeyError:
            avail = sorted(self._fields)
            hint = ", ".join(avail[:6]) + (" ..." if len(avail) > 6 else "")
            raise KeyError(
                f"{self.name} has no field {name!r} (have: {hint or '<none>'})"
            ) from None

    def static_field(self, name: str) -> FieldInfo:
        f = self.field(name)
        if not f.is_static:
            raise ValueError(f"{self.name}::{name} is an instance field")
        return f

    def has_field(self, name: str) -> bool:
        return name in self._fields

    def fields(self) -> list[FieldInfo]:
        return list(self._fields.values())

    def __repr__(self) -> str:
        return f"Type({self.name}, size={self.size}, fields={len(self._fields)})"


# --- VMMeta ---------------------------------------------------------------

class VMMeta:
    """Data-driven view of a HotSpot jvm.dll's VMStructs metadata."""

    _STRUCT_KEYS: ClassVar[list[str]] = [
        "TypeName", "FieldName", "TypeString",
        "IsStatic", "Offset", "Address", "ArrayStride",
    ]
    _TYPE_KEYS: ClassVar[list[str]] = [
        "TypeName", "SuperclassName", "IsOopType",
        "IsIntegerType", "IsUnsigned", "Size", "ArrayStride",
    ]
    _CONST_KEYS: ClassVar[list[str]] = ["Name", "Value", "ArrayStride"]

    def __init__(self, reader: Reader):
        self._reader = reader
        self._types: dict[str, TypeInfo] = {}
        self._int_consts: dict[str, int] = {}
        self._long_consts: dict[str, int] = {}
        self._load()

    # --- construction -------------------------------------------------------

    @classmethod
    def from_dll(cls, path: str) -> VMMeta:
        return cls(LocalReader(path))

    @classmethod
    def from_pid(cls, pid: int, module_name: str = "jvm.dll") -> VMMeta:
        # Lazy import to avoid pulling Toolhelp bindings when unused.
        from remote import RemoteReader
        return cls(RemoteReader(pid, module_name))

    @property
    def reader(self) -> Reader:
        return self._reader

    def close(self) -> None:
        self._reader.close()

    def __enter__(self):           return self
    def __exit__(self, *_exc):     self.close()

    # --- internal parsing ---------------------------------------------------

    def _layout(self, prefix: str, keys: list[str]) -> dict[str, int]:
        out = {}
        for k in keys:
            sym = f"{prefix}{k}" if k == "ArrayStride" else f"{prefix}{k}Offset"
            out[k] = _size_t(self._reader, self._reader.symbol(sym))
        return out

    def _load(self) -> None:
        r = self._reader
        sL = self._layout("gHotSpotVMStructEntry", self._STRUCT_KEYS)
        tL = self._layout("gHotSpotVMTypeEntry",   self._TYPE_KEYS)

        # Types first — structs refer to them by name.
        p = _ptr(r, r.symbol("gHotSpotVMTypes"))
        while True:
            tn_ptr = _ptr(r, p + tL["TypeName"])
            if not tn_ptr:
                break
            name = r.cstring(tn_ptr)
            self._types[name] = TypeInfo(
                name=name,
                super_name=r.cstring(_ptr(r, p + tL["SuperclassName"])),
                size=_u64(r, p + tL["Size"]),
                is_oop=_i32(r, p + tL["IsOopType"]) != 0,
                is_integer=_i32(r, p + tL["IsIntegerType"]) != 0,
                is_unsigned=_i32(r, p + tL["IsUnsigned"]) != 0,
            )
            p += tL["ArrayStride"]

        # Fields attach to types. Entries referencing an unknown type are
        # tolerated (can happen for VM-only helpers) and silently dropped.
        p = _ptr(r, r.symbol("gHotSpotVMStructs"))
        while True:
            tn_ptr = _ptr(r, p + sL["TypeName"])
            if not tn_ptr:
                break
            t_name = r.cstring(tn_ptr)
            f_name = r.cstring(_ptr(r, p + sL["FieldName"]))
            is_static = _i32(r, p + sL["IsStatic"]) != 0
            info = FieldInfo(
                type_name=t_name,
                name=f_name,
                type_string=r.cstring(_ptr(r, p + sL["TypeString"])),
                is_static=is_static,
                offset=0 if is_static else _u64(r, p + sL["Offset"]),
                address=_ptr(r, p + sL["Address"]) if is_static else 0,
            )
            t = self._types.get(t_name)
            if t is not None:
                t._fields[f_name] = info
            p += sL["ArrayStride"]

        # Constants — layout descriptors may be missing on exotic builds.
        self._int_consts = self._load_consts(
            "gHotSpotVMIntConstantEntry", "gHotSpotVMIntConstants", as_signed=True)
        self._long_consts = self._load_consts(
            "gHotSpotVMLongConstantEntry", "gHotSpotVMLongConstants", as_signed=False)

    def _load_consts(self, entry_prefix: str, array_sym: str,
                     as_signed: bool) -> dict[str, int]:
        r = self._reader
        out: dict[str, int] = {}
        try:
            L = self._layout(entry_prefix, self._CONST_KEYS)
        except KeyError:
            return out
        base = r.opt_symbol(array_sym)
        if not base:
            return out
        p = _ptr(r, base)
        read_val = _i32 if as_signed else _u64
        while True:
            n_ptr = _ptr(r, p + L["Name"])
            if not n_ptr:
                break
            out[r.cstring(n_ptr)] = read_val(r, p + L["Value"])
            p += L["ArrayStride"]
        return out

    # --- public query API ---------------------------------------------------

    def type(self, name: str) -> TypeInfo:
        try:
            return self._types[name]
        except KeyError:
            raise KeyError(
                f"type {name!r} not in vmStructs ({len(self._types)} known)"
            ) from None

    def has_type(self, name: str) -> bool:
        return name in self._types

    def types(self) -> list[TypeInfo]:
        return list(self._types.values())

    def int_constant(self, name: str) -> int:
        return self._int_consts[name]

    def long_constant(self, name: str) -> int:
        return self._long_consts[name]

    def constant(self, name: str) -> int:
        """Lookup in int constants first, then long. Raises if unknown."""
        if name in self._int_consts:
            return self._int_consts[name]
        if name in self._long_consts:
            return self._long_consts[name]
        raise KeyError(f"VM constant {name!r} not found")

    def int_constants(self) -> dict[str, int]:
        return dict(self._int_consts)

    def long_constants(self) -> dict[str, int]:
        return dict(self._long_consts)

    def __repr__(self) -> str:
        return (f"VMMeta({self._reader!r}, types={len(self._types)}, "
                f"int_consts={len(self._int_consts)}, "
                f"long_consts={len(self._long_consts)})")
