"""Method walker + bytecode patcher.

Enumerates every Java method in an InstanceKlass and exposes just enough
of its structure to read its name/signature and rewrite its bytecode.

The bytecode-rewrite path underpins our invoke hack: we can't call
JavaCalls::call() from a non-JavaThread, but we can replace a method's
body and then let the target invoke that method naturally. JIT-compiled
versions are invalidated so the new bytecode actually runs.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from vm_meta import VMMeta, _i32, _ptr, _u16
from field_reader import _ConstantPool


@dataclass(frozen=True)
class MethodSnapshot:
    address: int         # Method*
    const_method: int    # ConstMethod*
    name: str
    signature: str
    code_size: int       # length of the bytecode stream
    code_base: int       # absolute address of the first bytecode byte


def _array_methods(vm: VMMeta, klass_ptr: int) -> list[int]:
    """Return raw Method* pointers in InstanceKlass._methods."""
    r = vm.reader
    ik = vm.type("InstanceKlass")
    arr = _ptr(r, klass_ptr + ik.field("_methods").offset)
    if not arr:
        return []
    length = _i32(r, arr + 0)
    if length <= 0:
        return []
    raw = r.read(arr + 8, length * 8)
    return [struct.unpack_from("<Q", raw, i * 8)[0] for i in range(length)]


def methods_of(vm: VMMeta, klass_ptr: int) -> list[MethodSnapshot]:
    r = vm.reader
    method_t = vm.type("Method")
    cm_t = vm.type("ConstMethod")
    off_constmethod = method_t.field("_constMethod").offset
    off_name_idx = cm_t.field("_name_index").offset
    off_sig_idx = cm_t.field("_signature_index").offset
    off_code_size = cm_t.field("_code_size").offset
    off_cp = cm_t.field("_constants").offset
    header_size = cm_t.size  # bytecode starts right after the C++ header

    out: list[MethodSnapshot] = []
    for m_ptr in _array_methods(vm, klass_ptr):
        if not m_ptr:
            continue
        cm = _ptr(r, m_ptr + off_constmethod)
        if not cm:
            continue
        cp_ptr = _ptr(r, cm + off_cp)
        cp = _ConstantPool(vm, cp_ptr)
        name = cp.symbol(_u16(r, cm + off_name_idx))
        sig = cp.symbol(_u16(r, cm + off_sig_idx))
        code_size = _u16(r, cm + off_code_size)
        out.append(MethodSnapshot(
            address=m_ptr,
            const_method=cm,
            name=name,
            signature=sig,
            code_size=code_size,
            code_base=cm + header_size,
        ))
    return out


def find_method(vm: VMMeta, klass_ptr: int,
                name: str, signature: str | None = None
                ) -> MethodSnapshot | None:
    for m in methods_of(vm, klass_ptr):
        if m.name != name:
            continue
        if signature is not None and m.signature != signature:
            continue
        return m
    return None


# ---------------------------------------------------------------------------
# Bytecode patching
# ---------------------------------------------------------------------------

# Opcodes we care about:
#   0x00 — nop                    (single-byte padding)
#   0xB1 — return (void)          (returns from a V method)
#   0xAC — ireturn                (returns int from the top of stack)
#   0xAD — lreturn, 0xAE — freturn, 0xAF — dreturn, 0xB0 — areturn
_RETURN_VOID = 0xB1
_NOP = 0x00


def rewrite_method_body(
        vm: VMMeta, method: MethodSnapshot, new_bytecode: bytes) -> None:
    """Overwrite a method's bytecode in-place and invalidate the JIT version.

    `new_bytecode` must be <= method.code_size. The tail is padded with nops
    so interpreter dispatch never walks past the logical end.
    """
    if len(new_bytecode) > method.code_size:
        raise ValueError(
            f"new bytecode is {len(new_bytecode)}B but slot is "
            f"{method.code_size}B (can't grow without reallocating ConstMethod)")

    r = vm.reader
    method_t = vm.type("Method")

    # 1. Rewrite the bytecode stream. Padding matters because some code
    #    paths (e.g. verifier re-runs, reflection) walk the whole slot.
    padded = new_bytecode + bytes([_NOP] * (method.code_size - len(new_bytecode)))
    r.write(method.code_base, padded)

    # 2. Invalidate any JIT-compiled body: null out `_code` and reset the
    #    entry trampolines to the interpreter-to-interpreter stub.
    #    Without this, the target would keep calling the old compiled form.
    r.write(method.address + method_t.field("_code").offset,
            struct.pack("<Q", 0))

    if method_t.has_field("_i2i_entry"):
        i2i = _ptr(r, method.address + method_t.field("_i2i_entry").offset)
        if i2i:
            fci_off = method_t.field("_from_compiled_entry").offset
            fie_off = method_t.field("_from_interpreted_entry").offset
            r.write(method.address + fci_off, struct.pack("<Q", i2i))
            r.write(method.address + fie_off, struct.pack("<Q", i2i))


def make_nop_return(method: MethodSnapshot) -> bytes:
    """Build bytecode that immediately returns (for a V-type method).

    Caller must confirm the method signature matches the return opcode;
    only void methods may use `return` (0xB1)."""
    return bytes([_RETURN_VOID])
