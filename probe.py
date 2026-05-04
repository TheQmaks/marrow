"""Cross-version dump of HotSpot's self-describing VM metadata.

Reads gHotSpotVMStructs / gHotSpotVMTypes plus the layout-descriptor globals
from jvm.dll (JDK 8..25) via in-process LoadLibraryEx. No VM is started —
the arrays live in .rdata and are valid immediately after load.

Output is sorted and diffable: feed two dumps to `diff` to see exactly what
changed between HotSpot versions.
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as wt
import sys

_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.LoadLibraryExW.argtypes = [wt.LPCWSTR, wt.HANDLE, wt.DWORD]
_k32.LoadLibraryExW.restype = wt.HMODULE
_k32.GetProcAddress.argtypes = [wt.HMODULE, ctypes.c_char_p]
_k32.GetProcAddress.restype = ctypes.c_void_p
_k32.FreeLibrary.argtypes = [wt.HMODULE]

DONT_RESOLVE_DLL_REFS = 0x00000001

STRUCT_KEYS = ["TypeName", "FieldName", "TypeString",
               "IsStatic", "Offset", "Address", "ArrayStride"]
TYPE_KEYS = ["TypeName", "SuperclassName", "IsOopType",
             "IsIntegerType", "IsUnsigned", "Size", "ArrayStride"]


def _fatal(msg: str) -> None:
    print(f"[FATAL] {msg}", file=sys.stderr)
    sys.exit(2)


def _resolve(h: int, name: str) -> int:
    addr = _k32.GetProcAddress(h, name.encode("ascii"))
    if not addr:
        _fatal(f"missing export: {name}")
    return addr


def _size_t(addr: int) -> int: return ctypes.c_size_t.from_address(addr).value
def _ptr   (addr: int) -> int: return ctypes.c_void_p.from_address(addr).value or 0
def _i32   (addr: int) -> int: return ctypes.c_int32 .from_address(addr).value
def _u64   (addr: int) -> int: return ctypes.c_uint64.from_address(addr).value


def _cstr(addr: int) -> str:
    if not addr:
        return ""
    return ctypes.string_at(addr).decode("utf-8", errors="replace")


def _load_layout(h: int, prefix: str, keys: list[str]) -> dict[str, int]:
    out = {}
    for k in keys:
        sym = f"{prefix}{k}" if k == "ArrayStride" else f"{prefix}{k}Offset"
        out[k] = _size_t(_resolve(h, sym))
    return out


def _parse_structs(base: int, L: dict[str, int]) -> list[dict]:
    out, p = [], base
    while True:
        tn_ptr = _ptr(p + L["TypeName"])
        if not tn_ptr:
            break
        out.append({
            "typeName":   _cstr(tn_ptr),
            "fieldName":  _cstr(_ptr(p + L["FieldName"])),
            "typeString": _cstr(_ptr(p + L["TypeString"])),
            "isStatic":   _i32(p + L["IsStatic"]) != 0,
            "offset":     _u64(p + L["Offset"]),
            "address":    _ptr(p + L["Address"]),
        })
        p += L["ArrayStride"]
    return out


def _parse_types(base: int, L: dict[str, int]) -> list[dict]:
    out, p = [], base
    while True:
        tn_ptr = _ptr(p + L["TypeName"])
        if not tn_ptr:
            break
        out.append({
            "typeName":       _cstr(tn_ptr),
            "superclassName": _cstr(_ptr(p + L["SuperclassName"])),
            "isOopType":      _i32(p + L["IsOopType"]) != 0,
            "isIntegerType":  _i32(p + L["IsIntegerType"]) != 0,
            "isUnsigned":     _i32(p + L["IsUnsigned"]) != 0,
            "size":           _u64(p + L["Size"]),
        })
        p += L["ArrayStride"]
    return out


def dump(dll_path: str) -> int:
    h = _k32.LoadLibraryExW(dll_path, None, DONT_RESOLVE_DLL_REFS)
    if not h:
        _fatal(f"LoadLibraryEx({dll_path}) failed: {ctypes.get_last_error()}")

    sL = _load_layout(h, "gHotSpotVMStructEntry", STRUCT_KEYS)
    tL = _load_layout(h, "gHotSpotVMTypeEntry",   TYPE_KEYS)

    structs = _parse_structs(_ptr(_resolve(h, "gHotSpotVMStructs")), sL)
    types   = _parse_types  (_ptr(_resolve(h, "gHotSpotVMTypes")),   tL)

    static_cnt = sum(1 for s in structs if s["isStatic"])
    inst_cnt = len(structs) - static_cnt

    print(f"## source: {dll_path}")
    print("## struct-layout: "
          f"stride={sL['ArrayStride']} tn@{sL['TypeName']} fn@{sL['FieldName']} "
          f"ts@{sL['TypeString']} st@{sL['IsStatic']} off@{sL['Offset']} "
          f"addr@{sL['Address']}")
    print("## type-layout:   "
          f"stride={tL['ArrayStride']} tn@{tL['TypeName']} sup@{tL['SuperclassName']} "
          f"oop@{tL['IsOopType']} int@{tL['IsIntegerType']} "
          f"uns@{tL['IsUnsigned']} sz@{tL['Size']}")
    print(f"## counts: types={len(types)} structs={len(structs)} "
          f"(instance={inst_cnt} static={static_cnt})\n")

    for t in sorted(types, key=lambda x: x["typeName"]):
        flags = []
        if t["isOopType"]:     flags.append("oop")
        if t["isIntegerType"]: flags.append("int")
        if t["isUnsigned"]:    flags.append("unsigned")
        tag = (" " + " ".join(flags)) if flags else ""
        print(f"[type] {t['typeName']} size={t['size']}{tag} super={t['superclassName']}")

    for s in sorted(structs, key=lambda x: (x["typeName"], x["fieldName"])):
        if s["isStatic"]:
            print(f"[sfield] {s['typeName']}::{s['fieldName']} : {s['typeString']}")
        else:
            print(f"[field]  {s['typeName']}::{s['fieldName']} : "
                  f"{s['typeString']} offset={s['offset']}")

    _k32.FreeLibrary(h)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("dll", help="path to jvm.dll")
    args = ap.parse_args()
    return dump(args.dll)


if __name__ == "__main__":
    sys.exit(main())
