// agent_disasm.cpp — JVM bytecode disassembler binding.
// Exposes Marrow._disasm(method_lo, method_hi) -> Array<{pc,op,name,raw}>.
//
// Limitations:
//   tableswitch (0xAA), lookupswitch (0xAB), and wide (0xC4) have variable
//   operand sizes. This implementation stops disassembly at the first such
//   opcode and emits a marker entry with raw="<variable; disasm stopped>".
//   Full switch-table decoding is not implemented in this version.

#include "agent_modules.hpp"
#include "agent_helpers.hpp"
#include "vm_meta.hpp"
#include "duktape.h"

#include <cstdio>
#include <cstdint>

namespace marrow {

// ---------------------------------------------------------------------------
// Opcode table — 256 entries, JVM SE 17 instruction set.
// operand_bytes == -1 means variable-length (handled as stop-and-marker).
// ---------------------------------------------------------------------------
struct OpInfo { const char* name; int operand_bytes; };

static const OpInfo OPS[256] = {
    /* 0x00 */ {"nop",           0},
    /* 0x01 */ {"aconst_null",   0},
    /* 0x02 */ {"iconst_m1",     0},
    /* 0x03 */ {"iconst_0",      0},
    /* 0x04 */ {"iconst_1",      0},
    /* 0x05 */ {"iconst_2",      0},
    /* 0x06 */ {"iconst_3",      0},
    /* 0x07 */ {"iconst_4",      0},
    /* 0x08 */ {"iconst_5",      0},
    /* 0x09 */ {"lconst_0",      0},
    /* 0x0A */ {"lconst_1",      0},
    /* 0x0B */ {"fconst_0",      0},
    /* 0x0C */ {"fconst_1",      0},
    /* 0x0D */ {"fconst_2",      0},
    /* 0x0E */ {"dconst_0",      0},
    /* 0x0F */ {"dconst_1",      0},
    /* 0x10 */ {"bipush",        1},
    /* 0x11 */ {"sipush",        2},
    /* 0x12 */ {"ldc",           1},
    /* 0x13 */ {"ldc_w",         2},
    /* 0x14 */ {"ldc2_w",        2},
    /* 0x15 */ {"iload",         1},
    /* 0x16 */ {"lload",         1},
    /* 0x17 */ {"fload",         1},
    /* 0x18 */ {"dload",         1},
    /* 0x19 */ {"aload",         1},
    /* 0x1A */ {"iload_0",       0},
    /* 0x1B */ {"iload_1",       0},
    /* 0x1C */ {"iload_2",       0},
    /* 0x1D */ {"iload_3",       0},
    /* 0x1E */ {"lload_0",       0},
    /* 0x1F */ {"lload_1",       0},
    /* 0x20 */ {"lload_2",       0},
    /* 0x21 */ {"lload_3",       0},
    /* 0x22 */ {"fload_0",       0},
    /* 0x23 */ {"fload_1",       0},
    /* 0x24 */ {"fload_2",       0},
    /* 0x25 */ {"fload_3",       0},
    /* 0x26 */ {"dload_0",       0},
    /* 0x27 */ {"dload_1",       0},
    /* 0x28 */ {"dload_2",       0},
    /* 0x29 */ {"dload_3",       0},
    /* 0x2A */ {"aload_0",       0},
    /* 0x2B */ {"aload_1",       0},
    /* 0x2C */ {"aload_2",       0},
    /* 0x2D */ {"aload_3",       0},
    /* 0x2E */ {"iaload",        0},
    /* 0x2F */ {"laload",        0},
    /* 0x30 */ {"faload",        0},
    /* 0x31 */ {"daload",        0},
    /* 0x32 */ {"aaload",        0},
    /* 0x33 */ {"baload",        0},
    /* 0x34 */ {"caload",        0},
    /* 0x35 */ {"saload",        0},
    /* 0x36 */ {"istore",        1},
    /* 0x37 */ {"lstore",        1},
    /* 0x38 */ {"fstore",        1},
    /* 0x39 */ {"dstore",        1},
    /* 0x3A */ {"astore",        1},
    /* 0x3B */ {"istore_0",      0},
    /* 0x3C */ {"istore_1",      0},
    /* 0x3D */ {"istore_2",      0},
    /* 0x3E */ {"istore_3",      0},
    /* 0x3F */ {"lstore_0",      0},
    /* 0x40 */ {"lstore_1",      0},
    /* 0x41 */ {"lstore_2",      0},
    /* 0x42 */ {"lstore_3",      0},
    /* 0x43 */ {"fstore_0",      0},
    /* 0x44 */ {"fstore_1",      0},
    /* 0x45 */ {"fstore_2",      0},
    /* 0x46 */ {"fstore_3",      0},
    /* 0x47 */ {"dstore_0",      0},
    /* 0x48 */ {"dstore_1",      0},
    /* 0x49 */ {"dstore_2",      0},
    /* 0x4A */ {"dstore_3",      0},
    /* 0x4B */ {"astore_0",      0},
    /* 0x4C */ {"astore_1",      0},
    /* 0x4D */ {"astore_2",      0},
    /* 0x4E */ {"astore_3",      0},
    /* 0x4F */ {"iastore",       0},
    /* 0x50 */ {"lastore",       0},
    /* 0x51 */ {"fastore",       0},
    /* 0x52 */ {"dastore",       0},
    /* 0x53 */ {"aastore",       0},
    /* 0x54 */ {"bastore",       0},
    /* 0x55 */ {"castore",       0},
    /* 0x56 */ {"sastore",       0},
    /* 0x57 */ {"pop",           0},
    /* 0x58 */ {"pop2",          0},
    /* 0x59 */ {"dup",           0},
    /* 0x5A */ {"dup_x1",        0},
    /* 0x5B */ {"dup_x2",        0},
    /* 0x5C */ {"dup2",          0},
    /* 0x5D */ {"dup2_x1",       0},
    /* 0x5E */ {"dup2_x2",       0},
    /* 0x5F */ {"swap",          0},
    /* 0x60 */ {"iadd",          0},
    /* 0x61 */ {"ladd",          0},
    /* 0x62 */ {"fadd",          0},
    /* 0x63 */ {"dadd",          0},
    /* 0x64 */ {"isub",          0},
    /* 0x65 */ {"lsub",          0},
    /* 0x66 */ {"fsub",          0},
    /* 0x67 */ {"dsub",          0},
    /* 0x68 */ {"imul",          0},
    /* 0x69 */ {"lmul",          0},
    /* 0x6A */ {"fmul",          0},
    /* 0x6B */ {"dmul",          0},
    /* 0x6C */ {"idiv",          0},
    /* 0x6D */ {"ldiv",          0},
    /* 0x6E */ {"fdiv",          0},
    /* 0x6F */ {"ddiv",          0},
    /* 0x70 */ {"irem",          0},
    /* 0x71 */ {"lrem",          0},
    /* 0x72 */ {"frem",          0},
    /* 0x73 */ {"drem",          0},
    /* 0x74 */ {"ineg",          0},
    /* 0x75 */ {"lneg",          0},
    /* 0x76 */ {"fneg",          0},
    /* 0x77 */ {"dneg",          0},
    /* 0x78 */ {"ishl",          0},
    /* 0x79 */ {"lshl",          0},
    /* 0x7A */ {"ishr",          0},
    /* 0x7B */ {"lshr",          0},
    /* 0x7C */ {"iushr",         0},
    /* 0x7D */ {"lushr",         0},
    /* 0x7E */ {"iand",          0},
    /* 0x7F */ {"land",          0},
    /* 0x80 */ {"ior",           0},
    /* 0x81 */ {"lor",           0},
    /* 0x82 */ {"ixor",          0},
    /* 0x83 */ {"lxor",          0},
    /* 0x84 */ {"iinc",          2},
    /* 0x85 */ {"i2l",           0},
    /* 0x86 */ {"i2f",           0},
    /* 0x87 */ {"i2d",           0},
    /* 0x88 */ {"l2i",           0},
    /* 0x89 */ {"l2f",           0},
    /* 0x8A */ {"l2d",           0},
    /* 0x8B */ {"f2i",           0},
    /* 0x8C */ {"f2l",           0},
    /* 0x8D */ {"f2d",           0},
    /* 0x8E */ {"d2i",           0},
    /* 0x8F */ {"d2l",           0},
    /* 0x90 */ {"d2f",           0},
    /* 0x91 */ {"i2b",           0},
    /* 0x92 */ {"i2c",           0},
    /* 0x93 */ {"i2s",           0},
    /* 0x94 */ {"lcmp",          0},
    /* 0x95 */ {"fcmpl",         0},
    /* 0x96 */ {"fcmpg",         0},
    /* 0x97 */ {"dcmpl",         0},
    /* 0x98 */ {"dcmpg",         0},
    /* 0x99 */ {"ifeq",          2},
    /* 0x9A */ {"ifne",          2},
    /* 0x9B */ {"iflt",          2},
    /* 0x9C */ {"ifge",          2},
    /* 0x9D */ {"ifgt",          2},
    /* 0x9E */ {"ifle",          2},
    /* 0x9F */ {"if_icmpeq",     2},
    /* 0xA0 */ {"if_icmpne",     2},
    /* 0xA1 */ {"if_icmplt",     2},
    /* 0xA2 */ {"if_icmpge",     2},
    /* 0xA3 */ {"if_icmpgt",     2},
    /* 0xA4 */ {"if_icmple",     2},
    /* 0xA5 */ {"if_acmpeq",     2},
    /* 0xA6 */ {"if_acmpne",     2},
    /* 0xA7 */ {"goto",          2},
    /* 0xA8 */ {"jsr",           2},
    /* 0xA9 */ {"ret",           1},
    /* 0xAA */ {"tableswitch",  -1},  // variable — stop
    /* 0xAB */ {"lookupswitch", -1},  // variable — stop
    /* 0xAC */ {"ireturn",       0},
    /* 0xAD */ {"lreturn",       0},
    /* 0xAE */ {"freturn",       0},
    /* 0xAF */ {"dreturn",       0},
    /* 0xB0 */ {"areturn",       0},
    /* 0xB1 */ {"return",        0},
    /* 0xB2 */ {"getstatic",     2},
    /* 0xB3 */ {"putstatic",     2},
    /* 0xB4 */ {"getfield",      2},
    /* 0xB5 */ {"putfield",      2},
    /* 0xB6 */ {"invokevirtual", 2},
    /* 0xB7 */ {"invokespecial", 2},
    /* 0xB8 */ {"invokestatic",  2},
    /* 0xB9 */ {"invokeinterface",4},
    /* 0xBA */ {"invokedynamic", 4},
    /* 0xBB */ {"new",           2},
    /* 0xBC */ {"newarray",      1},
    /* 0xBD */ {"anewarray",     2},
    /* 0xBE */ {"arraylength",   0},
    /* 0xBF */ {"athrow",        0},
    /* 0xC0 */ {"checkcast",     2},
    /* 0xC1 */ {"instanceof",    2},
    /* 0xC2 */ {"monitorenter",  0},
    /* 0xC3 */ {"monitorexit",   0},
    /* 0xC4 */ {"wide",         -1},  // variable — stop
    /* 0xC5 */ {"multianewarray",3},
    /* 0xC6 */ {"ifnull",        2},
    /* 0xC7 */ {"ifnonnull",     2},
    /* 0xC8 */ {"goto_w",        4},
    /* 0xC9 */ {"jsr_w",         4},
    /* 0xCA */ {"_fast_agetfield",              2},
    /* 0xCB */ {"_fast_bgetfield",              2},
    /* 0xCC */ {"_fast_cgetfield",              2},
    /* 0xCD */ {"_fast_dgetfield",              2},
    /* 0xCE */ {"_fast_fgetfield",              2},
    /* 0xCF */ {"_fast_igetfield",              2},
    /* 0xD0 */ {"_fast_lgetfield",              2},
    /* 0xD1 */ {"_fast_sgetfield",              2},
    /* 0xD2 */ {"_fast_aputfield",              2},
    /* 0xD3 */ {"_fast_bputfield",              2},
    /* 0xD4 */ {"_fast_zputfield",              2},
    /* 0xD5 */ {"_fast_cputfield",              2},
    /* 0xD6 */ {"_fast_dputfield",              2},
    /* 0xD7 */ {"_fast_fputfield",              2},
    /* 0xD8 */ {"_fast_iputfield",              2},
    /* 0xD9 */ {"_fast_lputfield",              2},
    /* 0xDA */ {"_fast_sputfield",              2},
    /* 0xDB */ {"_fast_aload_0",                0},
    /* 0xDC */ {"_fast_iaccess_0",              1},
    /* 0xDD */ {"_fast_aaccess_0",              1},
    /* 0xDE */ {"_fast_faccess_0",              1},
    /* 0xDF */ {"_fast_iload",                  1},
    /* 0xE0 */ {"_fast_iload2",                 2},
    /* 0xE1 */ {"_fast_icaload",                1},
    /* 0xE2 */ {"_fast_invokevfinal",           2},
    /* 0xE3 */ {"_fast_linearswitch",          -1},  // variable — stop
    /* 0xE4 */ {"_fast_binaryswitch",          -1},  // variable — stop
    /* 0xE5 */ {"_fast_aldc",                   1},
    /* 0xE6 */ {"_fast_aldc_w",                 2},
    /* 0xE7 */ {"_return_register_finalizer",   0},
    /* 0xE8 */ {"_invokehandle",                2},
    /* 0xE9 */ {"_nofast_getfield",             2},
    /* 0xEA */ {"_nofast_putfield",             2},
    /* 0xEB */ {"_nofast_aload_0",              0},
    /* 0xEC */ {"_nofast_iload",                1},
    /* 0xED */ {"<reserved>",                   0},
    /* 0xEE */ {"<reserved>",                   0},
    /* 0xEF */ {"<reserved>",                   0},
    /* 0xF0 */ {"<reserved>",                   0},
    /* 0xF1 */ {"<reserved>",                   0},
    /* 0xF2 */ {"<reserved>",                   0},
    /* 0xF3 */ {"<reserved>",                   0},
    /* 0xF4 */ {"<reserved>",                   0},
    /* 0xF5 */ {"<reserved>",                   0},
    /* 0xF6 */ {"<reserved>",                   0},
    /* 0xF7 */ {"<reserved>",                   0},
    /* 0xF8 */ {"<reserved>",                   0},
    /* 0xF9 */ {"<reserved>",                   0},
    /* 0xFA */ {"<reserved>",                   0},
    /* 0xFB */ {"<reserved>",                   0},
    /* 0xFC */ {"<reserved>",                   0},
    /* 0xFD */ {"<reserved>",                   0},
    /* 0xFE */ {"<reserved>",                   0},
    /* 0xFF */ {"_shouldnotreachhere",           0},
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Push one instruction object onto the Duktape stack and insert into `arr`.
static void push_insn(duk_context* ctx, duk_idx_t arr, duk_uarridx_t idx,
                      int pc, int op, const char* name,
                      const uint8_t* bytes, int total_bytes) {
    char raw_buf[64] = {};
    char* p = raw_buf;
    for (int k = 0; k < total_bytes; ++k) {
        p += std::snprintf(p, raw_buf + sizeof(raw_buf) - p, "%02x ", bytes[k]);
    }
    // Trim trailing space.
    if (p > raw_buf) *(p - 1) = '\0';

    duk_idx_t o = duk_push_object(ctx);
    duk_push_int(ctx, pc);     duk_put_prop_string(ctx, o, "pc");
    duk_push_int(ctx, op);     duk_put_prop_string(ctx, o, "op");
    duk_push_string(ctx, name);duk_put_prop_string(ctx, o, "name");
    duk_push_string(ctx, raw_buf); duk_put_prop_string(ctx, o, "raw");
    duk_put_prop_index(ctx, arr, idx);
}

// ---------------------------------------------------------------------------
// Marrow._disasm(method_lo, method_hi) -> Array<{pc,op,name,raw}> | []
// ---------------------------------------------------------------------------
static duk_ret_t js_disasm(duk_context* ctx) {
    uint64_t method    = duk_require_uint(ctx, 0);
    uint64_t method_hi = duk_require_uint(ctx, 1);
    method |= (method_hi << 32);

    auto* vm = current_vm(ctx);
    duk_idx_t arr = duk_push_array(ctx);
    if (!vm) return 1;

    auto* mt  = vm->type("Method");
    auto* cmt = vm->type("ConstMethod");
    if (!mt || !cmt ||
        !mt->field("_constMethod") ||
        !cmt->field("_code_size")) {
        return 1;
    }

    uint64_t cm        = vm->reader()->read_u64(method + mt->field("_constMethod")->offset);
    uint16_t code_size = vm->reader()->read_u16(cm + cmt->field("_code_size")->offset);
    if (code_size == 0 || code_size > 65535) return 1;

    uint64_t code_base = cm + cmt->size;
    auto bytes = vm->reader()->read(code_base, code_size);

    duk_uarridx_t out_i = 0;
    int pc = 0;
    const int len = static_cast<int>(bytes.size());

    while (pc < len) {
        uint8_t op = bytes[static_cast<size_t>(pc)];
        const OpInfo& info = OPS[op];
        int operand_bytes = info.operand_bytes;

        if (operand_bytes < 0) {
            // Variable-length opcode: emit marker and stop.
            const uint8_t marker_byte = op;
            duk_idx_t o = duk_push_object(ctx);
            duk_push_int(ctx, pc);             duk_put_prop_string(ctx, o, "pc");
            duk_push_int(ctx, op);             duk_put_prop_string(ctx, o, "op");
            duk_push_string(ctx, info.name);   duk_put_prop_string(ctx, o, "name");
            duk_push_string(ctx, "<variable; disasm stopped>"); duk_put_prop_string(ctx, o, "raw");
            duk_put_prop_index(ctx, arr, out_i++);
            (void)marker_byte;
            break;
        }

        int total_bytes = 1 + operand_bytes;
        // Guard against reading past the buffer (malformed bytecode).
        if (pc + total_bytes > len) {
            total_bytes = len - pc;
        }

        push_insn(ctx, arr, out_i++, pc, op, info.name,
                  bytes.data() + pc,
                  total_bytes);
        pc += 1 + operand_bytes;
    }

    return 1;
}

// ---------------------------------------------------------------------------
// Registrar — called from install_bindings() in agent_js.cpp.
// ---------------------------------------------------------------------------
void register_disasm_bindings(void* duk_ctx, int ns_idx) {
    auto* ctx = static_cast<duk_context*>(duk_ctx);
    duk_push_c_function(ctx, js_disasm, 2);
    duk_put_prop_string(ctx, ns_idx, "_disasm");
}

} // namespace marrow
