#include "sysdict_hook.hpp"
#include <cstring>
#include <stdexcept>
#include <vector>

namespace marrow {

// Recognize the function prologue so we know how many bytes to splice
// onto the trampoline.
//   JDK 21: 40 53 56 57 48 83 EC 50        → 8 bytes
//   JDK 25: 48 89 5C 24 10 ...              → 5 bytes
static size_t classify_prologue(const uint8_t* buf) {
    if (buf[0] == 0x48 && buf[1] == 0x89 && buf[2] == 0x5C
        && buf[3] == 0x24 && buf[4] == 0x10)
        return 5;
    if (buf[0] == 0x40 && buf[1] == 0x53 && buf[2] == 0x56 && buf[3] == 0x57
        && buf[4] == 0x48 && buf[5] == 0x83 && buf[6] == 0xEC && buf[7] == 0x50)
        return 8;
    return 0;
}

// Wrapper shellcode. Compares RDX (const char* name) to `target_name`.
// If miss: tail-JMP to trampoline (== original function).
// If match: CALL trampoline (original runs, returns valid jclass handle
// whose slot contains donor's java.lang.Class oop), then we swap the
// oop at *handle from donor_mirror -> clone_mirror. Caller receives a
// real JNI local ref whose oop is our clone's mirror — all subsequent
// JNI ops succeed, reflection reflects the clone.
//
// Uses RIP-relative loads for tail data (name bytes, addresses).
static std::vector<uint8_t>
build_hook_shellcode(const std::string& target_name,
                      uint64_t trampoline, uint64_t donor_mirror,
                      uint64_t clone_mirror)
{
    std::vector<uint8_t> h;

    auto append = [&](std::initializer_list<uint8_t> bs) {
        for (uint8_t b : bs) h.push_back(b);
    };
    auto place_rel32 = [&](size_t instr_start, size_t target_off, size_t instr_len) {
        int32_t rel = int32_t(target_off - (instr_start + instr_len));
        std::memcpy(h.data() + instr_start + instr_len - 4, &rel, 4);
    };

    // === string compare ===
    // lea rax, [rip + name_off]         48 8D 05 rel32
    size_t lea_pos = h.size();
    append({0x48, 0x8D, 0x05, 0, 0, 0, 0});
    // mov r10, rdx                      49 89 D2
    append({0x49, 0x89, 0xD2});
    // .loop:
    size_t loop_pos = h.size();
    // movzx r11d, byte ptr [rax]        44 0F B6 18
    append({0x44, 0x0F, 0xB6, 0x18});
    // cmp r11b, byte ptr [r10]          45 3A 1A  -- actually: cmp byte, need proper
    // Easier: mov bl, [r10]; cmp r11b, bl — but rbx is non-volatile, need preserve.
    // Use another approach: movzx ecx... wait rcx is 1st arg. Use r9? It's 4th arg.
    // Let's spill r9 to stack temporarily. Actually:
    // movzx eax, byte ptr [r10] would clobber rax. Save rax first... too complex.
    //
    // Cleanest: use two single-byte compares via cmp m8, r11b (not allowed) —
    // instead, do xor method:
    //   mov cl, [r10]      ; rcx is env, we'd clobber! Need to preserve.
    //
    // We already need rcx/rdx/r8/r9 preserved for the call. So we MUST save
    // at least one scratch. Use the shadow space: save rcx at [rsp+0x08] (free
    // for callee). Then restore before call.
    //
    // Actually: `cmp r11b, byte ptr [r10]` — IS valid: REX.R + 3A + ModRM.
    // Encoding: cmp r11b, [r10]:  0x45 0x3A 0x1A   (opc 3A: cmp r8,r/m8; REX=45 -> R=1,B=1)
    append({0x45, 0x3A, 0x1A});
    // jne .miss (rel8 placeholder)      75 ??
    append({0x75, 0x00});
    size_t jne_miss_rel = h.size() - 1;
    // test r11b, r11b                   45 84 DB
    append({0x45, 0x84, 0xDB});
    // jz .match (rel8)                  74 ??
    append({0x74, 0x00});
    size_t jz_match_rel = h.size() - 1;
    // inc rax                           48 FF C0
    append({0x48, 0xFF, 0xC0});
    // inc r10                           49 FF C2
    append({0x49, 0xFF, 0xC2});
    // jmp .loop (rel8)                  EB ??
    // rel8 = target - (instr_start + instr_len), instr_len=2
    append({0xEB, uint8_t(int8_t(int(loop_pos) - int(h.size() + 2)))});

    // === .match ===
    size_t match_pos = h.size();
    h[jz_match_rel] = uint8_t(int8_t(int(match_pos) - int(jz_match_rel + 1)));
    // Alignment: at hook entry RSP & 0xF = 8. We need it 0 before call,
    // so `sub rsp, 0x28` (40 bytes = 32 shadow + 8 stack arg + 8 align).
    // sub rsp, 0x28                     48 83 EC 28
    append({0x48, 0x83, 0xEC, 0x28});
    // Copy caller's 5th arg (originally at [rsp+0x28] pre-sub → [rsp+0x50]
    // post-sub) to tramp's expected position [rsp+0x20] (which becomes
    // [tramp_rsp+0x28] after CALL pushes retaddr).
    //   mov r10, [rsp+0x50]             4C 8B 54 24 50
    append({0x4C, 0x8B, 0x54, 0x24, 0x50});
    //   mov [rsp+0x20], r10             4C 89 54 24 20
    append({0x4C, 0x89, 0x54, 0x24, 0x20});
    // call qword ptr [rip + tramp_off]  FF 15 rel32
    size_t call_tramp_pos = h.size();
    append({0xFF, 0x15, 0, 0, 0, 0});
    // add rsp, 0x28                     48 83 C4 28
    append({0x48, 0x83, 0xC4, 0x28});
    // test rax, rax                     48 85 C0
    append({0x48, 0x85, 0xC0});
    // jz .done (rel8)                   74 ??
    append({0x74, 0x00});
    size_t jz_done_rel = h.size() - 1;
    // mov r10, [rax]                    4C 8B 10
    append({0x4C, 0x8B, 0x10});
    // cmp r10, [rip + donor_ref]        4C 3B 15 rel32
    size_t cmp_donor_pos = h.size();
    append({0x4C, 0x3B, 0x15, 0, 0, 0, 0});
    // jne .done (rel8)                  75 ??
    append({0x75, 0x00});
    size_t jne_done_rel = h.size() - 1;
    // mov r10, [rip + clone_ref]        4C 8B 15 rel32
    size_t mov_clone_pos = h.size();
    append({0x4C, 0x8B, 0x15, 0, 0, 0, 0});
    // mov [rax], r10                    4C 89 10
    append({0x4C, 0x89, 0x10});
    // .done:
    size_t done_pos = h.size();
    h[jz_done_rel] = uint8_t(int8_t(int(done_pos) - int(jz_done_rel + 1)));
    h[jne_done_rel] = uint8_t(int8_t(int(done_pos) - int(jne_done_rel + 1)));
    // ret                               C3
    append({0xC3});

    // === .miss ===
    size_t miss_pos = h.size();
    h[jne_miss_rel] = uint8_t(int8_t(int(miss_pos) - int(jne_miss_rel + 1)));
    // jmp qword ptr [rip + tramp_off]   FF 25 rel32
    size_t jmp_tramp_pos = h.size();
    append({0xFF, 0x25, 0, 0, 0, 0});

    // === tail data ===
    while (h.size() % 8) h.push_back(0x90);
    size_t name_off = h.size();
    h.insert(h.end(), target_name.begin(), target_name.end());
    h.push_back(0);
    while (h.size() % 8) h.push_back(0x00);

    size_t tramp_ref_off = h.size();
    for (int i = 0; i < 8; ++i) h.push_back(uint8_t((trampoline >> (i * 8)) & 0xFF));

    size_t donor_ref_off = h.size();
    for (int i = 0; i < 8; ++i) h.push_back(uint8_t((donor_mirror >> (i * 8)) & 0xFF));

    size_t clone_ref_off = h.size();
    for (int i = 0; i < 8; ++i) h.push_back(uint8_t((clone_mirror >> (i * 8)) & 0xFF));

    // Patch all RIP-relative addresses.
    place_rel32(lea_pos, name_off, 7);
    place_rel32(call_tramp_pos, tramp_ref_off, 6);
    place_rel32(cmp_donor_pos, donor_ref_off, 7);
    place_rel32(mov_clone_pos, clone_ref_off, 7);
    place_rel32(jmp_tramp_pos, tramp_ref_off, 6);

    return h;
}

// Diagnostic: install a hook that ALWAYS tail-jumps to trampoline (no
// compare, no swap). Verifies the trampoline infrastructure alone.
SysDictHook install_sysdict_hook_passthrough(VMMeta* vm)
{
    Reader* r = vm->reader();
    auto orig = *r->opt_symbol("JVM_FindClassFromCaller");
    auto first = r->read(orig, 16);
    size_t N = classify_prologue(first.data());

    // Trampoline
    std::vector<uint8_t> tramp;
    tramp.insert(tramp.end(), first.begin(), first.begin() + N);
    tramp.push_back(0xFF); tramp.push_back(0x25);
    for (int i = 0; i < 4; ++i) tramp.push_back(0);
    uint64_t jmp_back = orig + N;
    for (int i = 0; i < 8; ++i) tramp.push_back(uint8_t((jmp_back >> (i*8)) & 0xFF));
    uint64_t tramp_page = r->alloc_near(orig, 0x1000, true);
    r->write(tramp_page, tramp.data(), tramp.size());

    // Hook that is just `jmp qword [rip+0]; dq tramp`
    std::vector<uint8_t> hook{0xFF, 0x25, 0, 0, 0, 0};
    for (int i = 0; i < 8; ++i) hook.push_back(uint8_t((tramp_page >> (i*8)) & 0xFF));
    uint64_t hook_page = r->alloc_near(orig, 0x1000, true);
    r->write(hook_page, hook.data(), hook.size());

    // Patch orig
    std::vector<uint8_t> patch(N, 0x90);
    patch[0] = 0xE9;
    int32_t rel = int32_t(int64_t(hook_page) - int64_t(orig) - 5);
    std::memcpy(patch.data() + 1, &rel, 4);
    r->write(orig, patch.data(), N);

    SysDictHook h{};
    h.original_fn = orig;
    h.hook_page = hook_page;
    h.trampoline_page = tramp_page;
    std::memcpy(h.orig_prologue, first.data(), N);
    h.prologue_len = N;
    return h;
}

SysDictHook install_sysdict_hook(VMMeta* vm, const std::string& target_name,
                                  uint64_t mirror_oop_donor_then_clone_packed)
{
    // mirror_oop_donor_then_clone_packed is actually the CLONE mirror oop
    // in the API signature (legacy). We need BOTH donor and clone mirrors
    // for the wrapper. Take donor from arg as-is; caller must pass it via
    // a side-channel. We re-parse: high 32 bits = donor (heap low 4GB in
    // compressed mode) — NO, we can't pack two wide oops.
    //
    // Change: caller must use install_sysdict_hook_full for both. Keep
    // legacy signature as an alias returning early.
    throw std::runtime_error(
        "install_sysdict_hook: use install_sysdict_hook_full(vm, name, "
        "donor_mirror_oop, clone_mirror_oop)");
}

// New entry-point with both mirrors.
SysDictHook install_sysdict_hook_full(VMMeta* vm, const std::string& target_name,
                                       uint64_t donor_mirror_oop,
                                       uint64_t clone_mirror_oop)
{
    if (target_name.size() > 60)
        throw std::runtime_error("target name too long");
    Reader* r = vm->reader();
    auto orig_opt = r->opt_symbol("JVM_FindClassFromCaller");
    if (!orig_opt)
        throw std::runtime_error("JVM_FindClassFromCaller not exported");
    uint64_t orig = *orig_opt;

    auto first = r->read(orig, 16);
    size_t N = classify_prologue(first.data());
    if (!N)
        throw std::runtime_error("unrecognized JVM_FindClassFromCaller prologue");

    // Trampoline = saved first N bytes + jmp qword [rip+0] to orig+N.
    std::vector<uint8_t> tramp;
    tramp.insert(tramp.end(), first.begin(), first.begin() + N);
    tramp.push_back(0xFF); tramp.push_back(0x25);
    for (int i = 0; i < 4; ++i) tramp.push_back(0);
    uint64_t jmp_back = orig + N;
    for (int i = 0; i < 8; ++i) tramp.push_back(uint8_t((jmp_back >> (i * 8)) & 0xFF));
    uint64_t tramp_page = r->alloc_near(orig, 0x1000, /*exec*/true);
    r->write(tramp_page, tramp.data(), tramp.size());

    // Build hook with both donor/clone embedded.
    auto hook = build_hook_shellcode(target_name, tramp_page,
                                      donor_mirror_oop, clone_mirror_oop);
    uint64_t hook_page = r->alloc_near(orig, 0x1000, /*exec*/true);
    r->write(hook_page, hook.data(), hook.size());

    // Patch orig[0..N] = JMP REL32 to hook_page, pad with nops.
    std::vector<uint8_t> patch(N, 0x90);
    patch[0] = 0xE9;
    int32_t jmp_rel = int32_t(int64_t(hook_page) - int64_t(orig) - 5);
    std::memcpy(patch.data() + 1, &jmp_rel, 4);
    r->write(orig, patch.data(), N);

    SysDictHook result{};
    result.original_fn = orig;
    result.hook_page = hook_page;
    result.trampoline_page = tramp_page;
    result.fake_handle_slot = 0;  // unused in wrapper variant
    result.clone_mirror = clone_mirror_oop;
    std::memcpy(result.orig_prologue, first.data(), N);
    result.prologue_len = N;
    return result;
}

void uninstall_sysdict_hook(VMMeta* vm, const SysDictHook& h)
{
    vm->reader()->write(h.original_fn, h.orig_prologue, h.prologue_len);
    vm->reader()->free(h.hook_page);
    vm->reader()->free(h.trampoline_page);
    if (h.fake_handle_slot) vm->reader()->free(h.fake_handle_slot);
}

} // namespace marrow
