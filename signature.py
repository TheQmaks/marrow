"""Java method-descriptor parser + CPCacheEntry._flags synthesizer.

HotSpot's legacy inline CPCacheEntry stores `_flags` with the method's
parameter size (in stack slots) at bits 0-7 and its Top-Of-Stack state
at bits 24-27. When we extend the cache with a new entry for a method
whose signature differs from our available donor template, we need to
patch those fields so the interpreter pops the right number of args
and dispatches to the correct return handler.
"""
from __future__ import annotations

# TosState enum from HotSpot `interp_masm*.hpp`. Values are stable.
TOS_BTOS = 0   # byte (also boolean is ztos=1)
TOS_ZTOS = 1
TOS_CTOS = 2
TOS_STOS = 3
TOS_ITOS = 4
TOS_LTOS = 5
TOS_FTOS = 6
TOS_DTOS = 7
TOS_ATOS = 8   # object/array reference
TOS_VTOS = 9   # void / no return value

_RET_TOS = {
    'V': TOS_VTOS, 'B': TOS_BTOS, 'Z': TOS_ZTOS, 'C': TOS_CTOS,
    'S': TOS_STOS, 'I': TOS_ITOS, 'J': TOS_LTOS, 'F': TOS_FTOS,
    'D': TOS_DTOS,
}


def parse_descriptor(sig: str, is_static: bool = True) -> tuple[int, int]:
    """Return (parameter_size_in_slots, return_TosState) for a JVM
    method descriptor like "(JI)V" or "(Ljava/lang/String;)J".

    Slot counting: I/F/B/S/C/Z/L/[ = 1 slot, J/D = 2 slots. The implicit
    `this` receiver is 1 slot for non-static; pass is_static=False.
    """
    assert sig.startswith('('), f"bad descriptor: {sig!r}"
    close = sig.rfind(')')
    args, ret = sig[1:close], sig[close + 1:]

    slots = 0 if is_static else 1
    i = 0
    while i < len(args):
        c = args[i]
        if c in 'BZSCIF':
            slots += 1; i += 1
        elif c in 'JD':
            slots += 2; i += 1
        elif c == 'L':
            slots += 1
            i = args.index(';', i) + 1
        elif c == '[':
            slots += 1
            while i < len(args) and args[i] == '[':
                i += 1
            if i < len(args) and args[i] == 'L':
                i = args.index(';', i) + 1
            elif i < len(args):
                i += 1
        else:
            raise ValueError(f"unexpected descriptor char {c!r} in {sig!r}")

    if not ret:
        raise ValueError(f"no return type in {sig!r}")
    if ret[0] in _RET_TOS:
        tos = _RET_TOS[ret[0]]
    elif ret[0] in 'L[':
        tos = TOS_ATOS
    else:
        raise ValueError(f"unknown return type {ret!r} in {sig!r}")
    return slots, tos


# ConstantPoolCacheEntry._flags packing (legacy layout, JDK 8..21):
#   bits  0..7  : size_of_parameters   (stack slots)
#   bits 24..27 : TosState              (4 bits)
# Higher bits carry feature flags (is_vfinal, is_final, is_volatile, …)
# which we preserve from the donor.
_PARAM_MASK = 0xFF
_TOS_SHIFT = 24
_TOS_MASK = 0xF << _TOS_SHIFT


def synth_flags_legacy(donor_flags: int, sig: str,
                        is_static: bool = True) -> int:
    """Return donor_flags with param size and TosState bits overwritten
    for the given method descriptor. Other bits are preserved."""
    slots, tos = parse_descriptor(sig, is_static=is_static)
    flags = donor_flags
    flags = (flags & ~_PARAM_MASK) | (slots & _PARAM_MASK)
    flags = (flags & ~_TOS_MASK) | ((tos & 0xF) << _TOS_SHIFT)
    return flags
