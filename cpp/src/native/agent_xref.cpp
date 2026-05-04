// agent_xref.cpp — x64 cross-reference walker.
// Disassembles a function body and extracts CALL targets + RIP-relative
// loads. Used to discover internal HotSpot symbols (JavaCalls::call,
// JavaThread::current, main_vm, ...) by walking *exported* JNI/JVM_*
// functions whose addresses we already have via GetProcAddress.
//
// Public C++ API (used by agent_javacall.cpp::resolve_symbol):
//   XrefScan marrow::xref_scan(uint64_t va, size_t max_insns);
//
// JS surface:
//   Marrow._xrefScan("0x7ff...", maxInsns) ->
//     {calls:[hex,...], jumps:[hex,...], ripRefs:[hex,...], stopReason:str}
//
// Walker scope: minimal x64 length-decoder that's ALSO aware of:
//   - E8 cd               CALL rel32
//   - E9 cd               JMP near rel32
//   - 0F 8x cd            Jcc rel32 (recorded as 'jumps' for analysis)
//   - REX.W? 8B /r mod=00 rm=101  MOV r64, [rip+disp32]
//   - REX.W? 8D /r mod=00 rm=101  LEA r64, [rip+disp32]
//   - REX.W? 89 /r mod=00 rm=101  MOV [rip+disp32], r64
//   - C3 / CC             RET / INT3 (terminate walk)
// Other instructions are length-decoded the same way as the inline-hook
// LDE; unknown opcodes terminate the walk to avoid mis-tracking.

#include "agent_modules.hpp"
#include "duktape.h"
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

namespace marrow {

struct XrefScan {
    std::vector<uint64_t> calls;     // absolute targets of CALL rel32
    std::vector<uint64_t> jumps;     // absolute targets of JMP/Jcc rel32
    std::vector<uint64_t> rip_refs;  // absolute addrs from RIP-rel MOV/LEA
    const char* stop_reason = "ok";  // "ok" / "ret" / "int3" / "unknown_op"
                                     // / "limit" / "bad_read"
    size_t insns_walked = 0;
};

namespace {

// ModRM helper — bytes consumed by ModRM + optional SIB + displacement,
// NOT counting ModRM itself. Returns -1 on inscrutable encodings.
static int modrm_extra(uint8_t modrm, const uint8_t* rest, size_t avail,
                       bool* is_rip_rel, int* disp_size_out)
{
    *is_rip_rel = false;
    *disp_size_out = 0;
    int mod = (modrm >> 6) & 3;
    int rm  = modrm & 7;
    if (mod == 3) return 0;
    int sib = (rm == 4) ? 1 : 0;
    int disp = 0;
    if (mod == 0) {
        if (rm == 5) {            // [rip+disp32] in 64-bit mode
            disp = 4;
            *is_rip_rel = true;
        }
        if (sib && (size_t)sib <= avail) {
            uint8_t sib_byte = rest[0];
            int base = sib_byte & 7;
            if (base == 5) disp = 4;   // [disp32] form
        }
    } else if (mod == 1) {
        disp = 1;
    } else { // mod == 2
        disp = 4;
    }
    *disp_size_out = disp;
    return sib + disp;
}

// Read a signed 32-bit displacement at `p`. Caller has verified 4 bytes
// are available.
static int32_t read_s32(const uint8_t* p) {
    int32_t v = 0;
    std::memcpy(&v, p, 4);
    return v;
}

// Decode one instruction at `p` (avail bytes available). Sets *length on
// return. If the instruction is a recognised xref form, populates
// `out_*` fields. Returns true on success, false on unknown / truncated.
struct InsnDetail {
    int  length = 0;
    bool is_call_rel32 = false;
    bool is_jmp_rel32  = false;
    bool is_jcc_rel32  = false;
    bool is_rip_rel_load_or_store = false;
    bool is_ret  = false;
    bool is_int3 = false;
    int32_t rel32 = 0;        // for call/jmp/jcc
    int32_t rip_disp32 = 0;   // for rip-rel
};

static bool decode_insn(const uint8_t* p, size_t avail, InsnDetail* out) {
    if (avail == 0) return false;
    *out = {};
    size_t off = 0;
    bool rex_w = false;
    bool has_66 = false;

    // Prefixes: REX, 66, F0/F2/F3.
    while (off < avail) {
        uint8_t b = p[off];
        if (b >= 0x40 && b <= 0x4F) { rex_w = (b & 0x08) != 0; ++off; }
        else if (b == 0x66)         { has_66 = true; ++off; }
        else if (b == 0xF0 || b == 0xF2 || b == 0xF3) { ++off; }
        else break;
    }
    (void)has_66;
    (void)rex_w;
    if (off >= avail) return false;
    uint8_t op = p[off++];

    // --- 1-byte opcodes ---
    if (op == 0x90) { out->length = (int)off; return true; }     // NOP
    if (op == 0xC3) { out->length = (int)off; out->is_ret  = true; return true; }
    if (op == 0xCB) { out->length = (int)off; out->is_ret  = true; return true; }
    if (op == 0xCC) { out->length = (int)off; out->is_int3 = true; return true; }
    if (op == 0x9C || op == 0x9D) { out->length = (int)off; return true; }
    if (op >= 0x50 && op <= 0x5F) { out->length = (int)off; return true; }
    if (op == 0x6A) {
        if (off >= avail) return false;
        out->length = (int)off + 1; return true;
    }
    if (op == 0x68) {
        if (off + 4 > avail) return false;
        out->length = (int)off + 4; return true;
    }

    // CALL rel32  (E8 cd)
    if (op == 0xE8) {
        if (off + 4 > avail) return false;
        out->rel32 = read_s32(p + off);
        out->is_call_rel32 = true;
        out->length = (int)off + 4;
        return true;
    }
    // JMP rel32   (E9 cd)
    if (op == 0xE9) {
        if (off + 4 > avail) return false;
        out->rel32 = read_s32(p + off);
        out->is_jmp_rel32 = true;
        out->length = (int)off + 4;
        return true;
    }
    // JMP rel8    (EB cb)
    if (op == 0xEB) {
        if (off + 1 > avail) return false;
        out->length = (int)off + 1;
        out->is_jmp_rel32 = false;   // rel8 — small forward; ignore for xref
        return true;
    }
    // Jcc rel8    (70..7F)
    if (op >= 0x70 && op <= 0x7F) {
        if (off + 1 > avail) return false;
        out->length = (int)off + 1; return true;
    }
    // Two-byte 0F xx
    if (op == 0x0F) {
        if (off >= avail) return false;
        uint8_t op2 = p[off++];
        // Jcc rel32  (0F 8x cd)
        if (op2 >= 0x80 && op2 <= 0x8F) {
            if (off + 4 > avail) return false;
            out->rel32 = read_s32(p + off);
            out->is_jcc_rel32 = true;
            out->length = (int)off + 4;
            return true;
        }
        // 0F 1F /0  multi-byte NOP w/ ModRM
        if (op2 == 0x1F) {
            if (off >= avail) return false;
            uint8_t modrm = p[off++];
            bool rr; int ds;
            int extra = modrm_extra(modrm, p + off, avail - off, &rr, &ds);
            if (extra < 0 || off + extra > avail) return false;
            out->length = (int)off + extra; return true;
        }
        // 0F B6/B7/BE/BF  movzx/movsx /r
        if (op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF) {
            if (off >= avail) return false;
            uint8_t modrm = p[off++];
            bool rr; int ds;
            int extra = modrm_extra(modrm, p + off, avail - off, &rr, &ds);
            if (extra < 0 || off + extra > avail) return false;
            out->length = (int)off + extra; return true;
        }
        // 0F 40..4F  CMOVcc r, r/m  (ModRM only)
        if (op2 >= 0x40 && op2 <= 0x4F) {
            if (off >= avail) return false;
            uint8_t modrm = p[off++];
            bool rr; int ds;
            int extra = modrm_extra(modrm, p + off, avail - off, &rr, &ds);
            if (extra < 0 || off + extra > avail) return false;
            out->length = (int)off + extra; return true;
        }
        // 0F AF  IMUL r, r/m  (ModRM only)
        // 0F A2  CPUID (no operand)
        // 0F 31  RDTSC, 0F 30  WRMSR — no operand
        if (op2 == 0xAF) {
            if (off >= avail) return false;
            uint8_t modrm = p[off++];
            bool rr; int ds;
            int extra = modrm_extra(modrm, p + off, avail - off, &rr, &ds);
            if (extra < 0 || off + extra > avail) return false;
            out->length = (int)off + extra; return true;
        }
        if (op2 == 0xA2 || op2 == 0x30 || op2 == 0x31 ||
            op2 == 0x05 /* SYSCALL */ || op2 == 0x06 /* CLTS */ ||
            op2 == 0x07 /* SYSRET */ || op2 == 0x77 /* EMMS */) {
            out->length = (int)off; return true;
        }
        // 0F 90..9F  SETcc r/m8  (ModRM only, byte target)
        if (op2 >= 0x90 && op2 <= 0x9F) {
            if (off >= avail) return false;
            uint8_t modrm = p[off++];
            bool rr; int ds;
            int extra = modrm_extra(modrm, p + off, avail - off, &rr, &ds);
            if (extra < 0 || off + extra > avail) return false;
            out->length = (int)off + extra; return true;
        }
        // 0F BA /r ib  BT/BTC/BTR/BTS r/m, imm8
        // 0F BC, 0F BD  BSF/BSR
        // 0F C0..C1  XADD r/m, r
        if (op2 == 0xBC || op2 == 0xBD || op2 == 0xC0 || op2 == 0xC1) {
            if (off >= avail) return false;
            uint8_t modrm = p[off++];
            bool rr; int ds;
            int extra = modrm_extra(modrm, p + off, avail - off, &rr, &ds);
            if (extra < 0 || off + extra > avail) return false;
            out->length = (int)off + extra; return true;
        }
        if (op2 == 0xBA) {
            if (off >= avail) return false;
            uint8_t modrm = p[off++];
            bool rr; int ds;
            int extra = modrm_extra(modrm, p + off, avail - off, &rr, &ds);
            if (extra < 0 || off + extra + 1 > avail) return false;
            out->length = (int)off + extra + 1; return true;
        }
        // 0F C8..CF  BSWAP r — single byte after 0F + register field embedded.
        if (op2 >= 0xC8 && op2 <= 0xCF) { out->length = (int)off; return true; }
        return false;   // unknown 0F xx
    }

    // --- ModRM-bearing common opcodes ---
    auto handle_modrm = [&](bool mark_rip_rel) -> bool {
        if (off >= avail) return false;
        uint8_t modrm = p[off++];
        bool rr; int ds;
        int extra = modrm_extra(modrm, p + off, avail - off, &rr, &ds);
        if (extra < 0 || off + extra > avail) return false;
        if (rr && mark_rip_rel) {
            // disp32 sits at p[off + sib_byte_count]; sib bit set when rm==4.
            int rm = modrm & 7;
            int sib = (rm == 4) ? 1 : 0;
            size_t disp_at = off + sib;
            if (disp_at + 4 <= avail) {
                out->rip_disp32 = read_s32(p + disp_at);
                out->is_rip_rel_load_or_store = true;
            }
        }
        out->length = (int)off + extra;
        return true;
    };

    // 88/89/8A/8B  MOV r/m, r  /  MOV r, r/m
    if (op == 0x88 || op == 0x89 || op == 0x8A || op == 0x8B) {
        return handle_modrm(/*mark_rip_rel=*/true);
    }
    // AL/EAX immediate group: 04/05 ADD, 0C/0D OR, 14/15 ADC, 1C/1D SBB,
    // 24/25 AND, 2C/2D SUB, 34/35 XOR, 3C/3D CMP. Even-byte = imm8,
    // odd-byte = imm32 (sign-extended in REX.W; encoding stays 4 bytes).
    {
        bool al_imm8  = (op == 0x04 || op == 0x0C || op == 0x14 || op == 0x1C ||
                          op == 0x24 || op == 0x2C || op == 0x34 || op == 0x3C);
        bool ax_imm32 = (op == 0x05 || op == 0x0D || op == 0x15 || op == 0x1D ||
                          op == 0x25 || op == 0x2D || op == 0x35 || op == 0x3D);
        if (al_imm8) {
            if (off + 1 > avail) return false;
            out->length = (int)off + 1; return true;
        }
        if (ax_imm32) {
            if (off + 4 > avail) return false;
            out->length = (int)off + 4; return true;
        }
    }
    // 00/01/02/03  ADD r/m, r  /  ADD r, r/m
    // 08/09/0A/0B  OR
    // 28/29/2A/2B  SUB
    // 38/39/3A/3B  CMP
    if (op == 0x00 || op == 0x01 || op == 0x02 || op == 0x03 ||
        op == 0x08 || op == 0x0A || op == 0x0B ||
        op == 0x28 || op == 0x29 || op == 0x2A || op == 0x2B ||
        op == 0x38 || op == 0x3A) {
        return handle_modrm(/*mark_rip_rel=*/false);
    }
    // F6/F7 group: TEST/NOT/NEG/MUL/IMUL/DIV/IDIV r/m, [imm].
    // /0 (TEST) carries an immediate (F6: imm8, F7: imm32). Others have no imm.
    if (op == 0xF6 || op == 0xF7) {
        if (off >= avail) return false;
        uint8_t modrm = p[off++];
        bool rr; int ds;
        int extra = modrm_extra(modrm, p + off, avail - off, &rr, &ds);
        if (extra < 0 || off + extra > avail) return false;
        int reg_field = (modrm >> 3) & 7;
        int imm_size = 0;
        if (reg_field == 0 || reg_field == 1) {  // /0 and /1 = TEST imm
            imm_size = (op == 0xF6) ? 1 : 4;
        }
        if (off + extra + imm_size > avail) return false;
        out->length = (int)off + extra + imm_size; return true;
    }
    // D1/D3 — shift r/m by 1 / by CL.
    if (op == 0xD1 || op == 0xD3) {
        return handle_modrm(false);
    }
    // C1 — shift r/m, imm8.
    if (op == 0xC1) {
        if (off >= avail) return false;
        uint8_t modrm = p[off++];
        bool rr; int ds;
        int extra = modrm_extra(modrm, p + off, avail - off, &rr, &ds);
        if (extra < 0 || off + extra + 1 > avail) return false;
        out->length = (int)off + extra + 1; return true;
    }
    // 6B — IMUL r, r/m, imm8;  69 — IMUL r, r/m, imm32
    if (op == 0x69 || op == 0x6B) {
        if (off >= avail) return false;
        uint8_t modrm = p[off++];
        bool rr; int ds;
        int extra = modrm_extra(modrm, p + off, avail - off, &rr, &ds);
        int imm = (op == 0x6B) ? 1 : 4;
        if (extra < 0 || off + extra + imm > avail) return false;
        out->length = (int)off + extra + imm; return true;
    }
    // 8E — MOV Sreg, r/m16 ; 8C — MOV r/m, Sreg (rare in HotSpot but safe to length).
    if (op == 0x8C || op == 0x8E) return handle_modrm(false);
    // A8 TEST AL, imm8 ; A9 TEST EAX, imm32 (also rax with REX.W — still 4 byte imm).
    if (op == 0xA8) {
        if (off + 1 > avail) return false;
        out->length = (int)off + 1; return true;
    }
    if (op == 0xA9) {
        if (off + 4 > avail) return false;
        out->length = (int)off + 4; return true;
    }
    // A0/A1 MOV AL/EAX, [moffs] ; A2/A3 MOV [moffs], AL/EAX.
    // Carry an 8-byte absolute offset. Rare but does appear in HotSpot.
    if (op == 0xA0 || op == 0xA1 || op == 0xA2 || op == 0xA3) {
        if (off + 8 > avail) return false;
        out->length = (int)off + 8; return true;
    }
    // C2 cw — RET imm16 ; C0/C1 already handled (shifts), this is RET-with-pop.
    if (op == 0xC2) {
        if (off + 2 > avail) return false;
        out->length = (int)off + 2; out->is_ret = true; return true;
    }
    // C6 /0 ib — MOV r/m8, imm8.
    if (op == 0xC6) {
        if (off >= avail) return false;
        uint8_t modrm = p[off++];
        bool rr; int ds;
        int extra = modrm_extra(modrm, p + off, avail - off, &rr, &ds);
        if (extra < 0 || off + extra + 1 > avail) return false;
        out->length = (int)off + extra + 1; return true;
    }
    // E3 cb — JECXZ rel8.
    if (op == 0xE3) {
        if (off + 1 > avail) return false;
        out->length = (int)off + 1; return true;
    }
    // FE /0 INC r/m8, /1 DEC r/m8 — modrm only.
    if (op == 0xFE) return handle_modrm(false);
    // 86/87 — XCHG r/m, r — modrm only.
    if (op == 0x86 || op == 0x87) return handle_modrm(false);
    // 90+rd — XCHG eax, r is the same byte as NOP (already covered for 0x90).
    if (op >= 0x91 && op <= 0x97) { out->length = (int)off; return true; }
    // 8D LEA r, m
    if (op == 0x8D) return handle_modrm(true);
    // 80 imm8 group  -- ALU r/m8, imm8 (cmp/add/sub/and/or/xor/test on byte).
    // Captures the rip_disp32 if RIP-relative (e.g., `cmp byte ptr [rip+...], 0`).
    if (op == 0x80) {
        if (off >= avail) return false;
        uint8_t modrm = p[off++];
        bool rr; int ds;
        int extra = modrm_extra(modrm, p + off, avail - off, &rr, &ds);
        if (extra < 0 || off + extra + 1 > avail) return false;
        if (rr) {
            int rm = modrm & 7;
            int sib = (rm == 4) ? 1 : 0;
            size_t disp_at = off + sib;
            if (disp_at + 4 <= avail) {
                out->rip_disp32 = read_s32(p + disp_at);
                out->is_rip_rel_load_or_store = true;
            }
        }
        out->length = (int)off + extra + 1; return true;
    }
    // 81 imm32 group
    if (op == 0x81) {
        if (off >= avail) return false;
        uint8_t modrm = p[off++];
        bool rr; int ds;
        int extra = modrm_extra(modrm, p + off, avail - off, &rr, &ds);
        if (extra < 0 || off + extra + 4 > avail) return false;
        if (rr) {
            int rm = modrm & 7;
            int sib = (rm == 4) ? 1 : 0;
            size_t disp_at = off + sib;
            if (disp_at + 4 <= avail) {
                out->rip_disp32 = read_s32(p + disp_at);
                out->is_rip_rel_load_or_store = true;
            }
        }
        out->length = (int)off + extra + 4; return true;
    }
    // 83 imm8 group
    if (op == 0x83) {
        if (off >= avail) return false;
        uint8_t modrm = p[off++];
        bool rr; int ds;
        int extra = modrm_extra(modrm, p + off, avail - off, &rr, &ds);
        if (extra < 0 || off + extra + 1 > avail) return false;
        if (rr) {
            int rm = modrm & 7;
            int sib = (rm == 4) ? 1 : 0;
            size_t disp_at = off + sib;
            if (disp_at + 4 <= avail) {
                out->rip_disp32 = read_s32(p + disp_at);
                out->is_rip_rel_load_or_store = true;
            }
        }
        out->length = (int)off + extra + 1; return true;
    }
    // 85/84/39/3B/09/0B/31/33/21/23  reg-reg arithmetic with ModRM
    if (op == 0x85 || op == 0x84 || op == 0x39 || op == 0x3B ||
        op == 0x09 || op == 0x0B || op == 0x31 || op == 0x33 ||
        op == 0x21 || op == 0x23) {
        return handle_modrm(false);
    }
    // B8..BF  MOV r, imm{32 or 64}
    if (op >= 0xB8 && op <= 0xBF) {
        int imm = rex_w ? 8 : 4;
        if (off + imm > avail) return false;
        out->length = (int)off + imm; return true;
    }
    // B0..B7  MOV r8, imm8
    if (op >= 0xB0 && op <= 0xB7) {
        if (off + 1 > avail) return false;
        out->length = (int)off + 1; return true;
    }
    // C7  MOV r/m, imm32
    if (op == 0xC7) {
        if (off >= avail) return false;
        uint8_t modrm = p[off++];
        bool rr; int ds;
        int extra = modrm_extra(modrm, p + off, avail - off, &rr, &ds);
        if (extra < 0 || off + extra + 4 > avail) return false;
        out->length = (int)off + extra + 4; return true;
    }
    // FF /r — covers FF /4 (JMP r/m), FF /6 (PUSH r/m), etc.
    // We only need length here; CALL [rip+...] uses FF /2 with ModRM.
    if (op == 0xFF) {
        if (off >= avail) return false;
        uint8_t modrm = p[off++];
        bool rr; int ds;
        int extra = modrm_extra(modrm, p + off, avail - off, &rr, &ds);
        if (extra < 0 || off + extra > avail) return false;
        // Note: we deliberately don't mark FF /2 [rip+...] as a call_rel32
        // — those resolve through an import/IAT slot (read at runtime).
        // Capture the IAT slot address as a rip_ref instead.
        if (rr) {
            int rm = modrm & 7;
            int sib = (rm == 4) ? 1 : 0;
            size_t disp_at = off + sib;
            if (disp_at + 4 <= avail) {
                out->rip_disp32 = read_s32(p + disp_at);
                out->is_rip_rel_load_or_store = true;
            }
        }
        out->length = (int)off + extra; return true;
    }

    return false;   // unknown opcode — caller stops walk
}

// Safe read N bytes from `va` into out[]. Returns false on access error
// (uses SEH translator from agent host so we don't crash on bad reads).
static bool seh_read(const void* va, size_t n, uint8_t* out) {
    __try {
        std::memcpy(out, va, n);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

} // anon

// Walk up to `max_insns` instructions starting at `va`. Stops on RET,
// INT3, unknown opcode, or instruction count.
XrefScan xref_scan(uint64_t va, size_t max_insns) {
    XrefScan sc;
    if (!va) { sc.stop_reason = "null"; return sc; }

    // Snapshot up to 4 KB so we don't ping-pong page reads. Most JNI
    // functions are < 1 KB; 4 KB covers all reasonable cases.
    constexpr size_t SNAP = 4096;
    uint8_t buf[SNAP];
    if (!seh_read(reinterpret_cast<const void*>(va), SNAP, buf)) {
        sc.stop_reason = "bad_read";
        return sc;
    }

    size_t off = 0;
    while (sc.insns_walked < max_insns && off < SNAP) {
        InsnDetail d;
        if (!decode_insn(buf + off, SNAP - off, &d)) {
            sc.stop_reason = "unknown_op";
            break;
        }
        if (d.length <= 0) { sc.stop_reason = "bad_len"; break; }
        uint64_t next_rip = va + off + (uint64_t)d.length;

        if (d.is_call_rel32) {
            sc.calls.push_back(next_rip + (int64_t)d.rel32);
        } else if (d.is_jmp_rel32 || d.is_jcc_rel32) {
            sc.jumps.push_back(next_rip + (int64_t)d.rel32);
        } else if (d.is_rip_rel_load_or_store) {
            sc.rip_refs.push_back(next_rip + (int64_t)d.rip_disp32);
        }

        off += d.length;
        ++sc.insns_walked;

        if (d.is_ret)  { sc.stop_reason = "ret";  break; }
        if (d.is_int3) { sc.stop_reason = "int3"; break; }
        // Unconditional JMP rel32 to outside is also a natural stop —
        // continuing past it would walk into unrelated code.
        if (d.is_jmp_rel32) { sc.stop_reason = "jmp"; break; }
    }
    if (sc.insns_walked >= max_insns) sc.stop_reason = "limit";
    return sc;
}

namespace {

// JS: Marrow._xrefScan(vaHex, maxInsns=128) ->
//   {calls:[hex,...], jumps:[hex,...], ripRefs:[hex,...],
//    stopReason:str, insnsWalked:N}
static duk_ret_t js_xref_scan(duk_context* c) {
    const char* va_str = duk_require_string(c, 0);
    int max_n          = duk_get_int_default(c, 1, 128);
    if (max_n <= 0 || max_n > 4096) max_n = 128;

    unsigned long long va = 0;
    {
        const char* s = va_str;
        if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
        std::sscanf(s, "%llx", &va);
    }

    auto sc = xref_scan(static_cast<uint64_t>(va), static_cast<size_t>(max_n));

    duk_idx_t obj = duk_push_object(c);
    auto push_arr = [&](const std::vector<uint64_t>& v, const char* key) {
        duk_idx_t a = duk_push_array(c);
        char buf[32];
        for (size_t i = 0; i < v.size(); ++i) {
            std::snprintf(buf, sizeof(buf), "0x%llx",
                          (unsigned long long)v[i]);
            duk_push_string(c, buf);
            duk_put_prop_index(c, a, duk_uarridx_t(i));
        }
        duk_put_prop_string(c, obj, key);
    };
    push_arr(sc.calls,    "calls");
    push_arr(sc.jumps,    "jumps");
    push_arr(sc.rip_refs, "ripRefs");
    duk_push_string(c, sc.stop_reason);
    duk_put_prop_string(c, obj, "stopReason");
    duk_push_int(c, (int)sc.insns_walked);
    duk_put_prop_string(c, obj, "insnsWalked");
    return 1;
}

} // anon

void register_xref_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_xref_scan, DUK_VARARGS);
    duk_put_prop_string(ctx, ns_idx, "_xrefScan");
}

} // namespace marrow
