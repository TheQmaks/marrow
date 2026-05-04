"""Native method-entry hooks via `_from_interpreted_entry` patching.

We allocate a tiny x64 trampoline inside the target process, point the
method's interpreter-entry (and compiled-entry, after JIT invalidation)
at it, and the trampoline increments a shared counter then tail-calls
the original entry so program behaviour is unchanged. Polling the
counter from our process gives us real pre-invocation hooks without
rewriting the method's bytecode.

Trampoline layout (x64, 52 bytes):

    off 0   9C                      pushfq
    off 1   50 51 52 41 50 41 51 41 52 41 53
                                    push rax, rcx, rdx, r8, r9, r10, r11
    off 12  48 B8 <counter_addr:8>  mov  rax, counter_addr  (imm64 @ off 14)
    off 22  F0 48 FF 00             lock inc qword ptr [rax]
    off 26  41 5B 41 5A 41 59 41 58 5A 59 58
                                    pop  r11, r10, r9, r8, rdx, rcx, rax
    off 37  9D                      popfq
    off 38  FF 25 00 00 00 00       jmp  qword ptr [rip + 0]
    off 44  <orig_entry:8>

Only the counter_addr (offset 14) and orig_entry (offset 44) are patched
per-install; everything else is a fixed template.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from vm_meta import VMMeta, _ptr, _u64
from method_walker import MethodSnapshot


_TRAMPOLINE_TEMPLATE = bytes.fromhex(
    "9C"                                 # pushfq
    "5051524150415141524153"             # push rax, rcx, rdx, r8, r9, r10, r11
    "48B8" "0000000000000000"            # mov rax, <counter_addr>  @ +13
    "F048FF00"                           # lock inc qword [rax]
    "415B415A415941585A5958"             # pop r11, r10, r9, r8, rdx, rcx, rax
    "9D"                                 # popfq
    "FF2500000000"                       # jmp qword ptr [rip+0]
    "0000000000000000"                   # <orig_entry>  @ +44
)
_COUNTER_PATCH_OFFSET = 14
_ORIG_ENTRY_PATCH_OFFSET = 44
assert len(_TRAMPOLINE_TEMPLATE) == 52, len(_TRAMPOLINE_TEMPLATE)


@dataclass
class MethodHook:
    vm: VMMeta
    method: MethodSnapshot
    counter_addr: int
    trampoline_addr: int
    original_interpreted_entry: int
    original_compiled_entry: int
    original_code: int

    def read_count(self) -> int:
        return _u64(self.vm.reader, self.counter_addr)

    def uninstall(self) -> None:
        """Restore all patched fields and free the allocated pages."""
        r = self.vm.reader
        method_t = self.vm.type("Method")
        r.write(self.method.address + method_t.field("_from_interpreted_entry").offset,
                struct.pack("<Q", self.original_interpreted_entry))
        r.write(self.method.address + method_t.field("_from_compiled_entry").offset,
                struct.pack("<Q", self.original_compiled_entry))
        r.write(self.method.address + method_t.field("_code").offset,
                struct.pack("<Q", self.original_code))
        r.free(self.trampoline_addr)
        r.free(self.counter_addr)


def install_counting_hook(vm: VMMeta, method: MethodSnapshot) -> MethodHook:
    """Plant a per-call counter in front of `method`. Works even if the
    method has been JIT-compiled: we null `_code` and point both the
    interpreted- and compiled-entry slots at our trampoline.
    """
    r = vm.reader
    method_t = vm.type("Method")

    # 1. Allocate counter (8 bytes, writable) and trampoline (52 bytes, exec).
    counter_addr = r.alloc(8, executable=False)
    trampoline_addr = r.alloc(len(_TRAMPOLINE_TEMPLATE), executable=True)
    r.write(counter_addr, b"\x00" * 8)

    # 2. Snapshot the fields we're about to overwrite so uninstall can undo.
    fie_off = method_t.field("_from_interpreted_entry").offset
    fce_off = method_t.field("_from_compiled_entry").offset
    code_off = method_t.field("_code").offset
    orig_fie = _ptr(r, method.address + fie_off)
    orig_fce = _ptr(r, method.address + fce_off)
    orig_code = _ptr(r, method.address + code_off)

    # 3. Build trampoline body with the two absolute addresses patched in.
    body = bytearray(_TRAMPOLINE_TEMPLATE)
    body[_COUNTER_PATCH_OFFSET:_COUNTER_PATCH_OFFSET + 8] = struct.pack("<Q", counter_addr)
    body[_ORIG_ENTRY_PATCH_OFFSET:_ORIG_ENTRY_PATCH_OFFSET + 8] = \
        struct.pack("<Q", orig_fie)
    r.write(trampoline_addr, bytes(body))

    # 4. Redirect the interpreted entry. Null out `_code` and steer the
    #    compiled entry at the trampoline too, so previously-compiled
    #    callers also go through us. Both entries eventually tail-call
    #    the ORIGINAL interpreter entry — by the time interpreter runs
    #    the method, there is no JIT version any more.
    r.write(method.address + code_off, struct.pack("<Q", 0))
    r.write(method.address + fie_off, struct.pack("<Q", trampoline_addr))
    r.write(method.address + fce_off, struct.pack("<Q", trampoline_addr))

    return MethodHook(
        vm=vm, method=method,
        counter_addr=counter_addr,
        trampoline_addr=trampoline_addr,
        original_interpreted_entry=orig_fie,
        original_compiled_entry=orig_fce,
        original_code=orig_code,
    )
