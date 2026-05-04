// C++ port CLI — attach by PID, list threads and classes.
// Matches demo_threads.py / demo_classes.py output for quick validation.

#include "reader.hpp"
#include "vm_meta.hpp"
#include "walker.hpp"
#include "oop_reader.hpp"
#include "field_reader.hpp"
#include "string_reader.hpp"
#include "zgc.hpp"
#include "heap_walker.hpp"
#include "barriers.hpp"
#include "method_walker.hpp"
#include "tlab.hpp"
#include "hooks.hpp"
#include "injector.hpp"
#include "klass_cloner.hpp"
#include "dict_analyzer.hpp"
#include "sysdict_hook.hpp"
#include "agent_ipc.hpp"
#include <chrono>
#include <thread>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>

using namespace marrow;

static void usage(const char* argv0) {
    std::fprintf(stderr,
        "usage:\n"
        "  %s dump <path\\to\\jvm.dll>                   # offline vmStructs dump\n"
        "  %s threads <pid>                             # list JavaThreads\n"
        "  %s classes <pid>                             # list loaded classes\n"
        "  %s read-string <pid> <klass> <field>         # decode String-typed field\n"
        "  %s instances <pid> <klass>                   # brute-force scan heap for instances\n"
        "  %s write-ref <pid> <klass> <field> <donor>   # overwrite static String ref by copying <donor>\n"
        "  %s methods <pid> <klass>                     # list methods on a class\n"
        "  %s mute <pid> <klass> <method>               # replace method body with `return` (void only)\n"
        "  %s alloc-ba <pid> <n>                        # allocate byte[n] via TLAB, print its oop\n"
        "  %s hook <pid> <klass> <method>               # install counting hook, poll for 2s\n"
        "  %s inject <pid> <dll_path>                   # CreateRemoteThread(LoadLibraryA)\n"
        "  %s hw-watch <pid> <addr> [slot]              # arm DR<slot> write-watch on all threads\n"
        "  %s clone-class <pid> <donor> <newname>       # clone an InstanceKlass, register via CLDG\n"
        "  %s clone-class-l2 <pid> <donor> <newname>    # L1 + clone methods/constmethods, patch 1 bytecode byte\n"
        "  %s dump-bytecode <pid> <klass> <method>      # print method's code_size bytes as hex\n"
        "  %s clone-class-l3 <pid> <donor> <newname>    # L1 + register clone in SystemDictionary (JDK 11/17)\n"
        "  %s replace-class <pid> <donor>               # swap Class.forName(donor) to a clone (JDK 11/17)\n"
        "  %s replace-class-hook <pid> <donor>          # same but via JVM_FindClassFromCaller hook (JDK 21/25)\n",
        argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0,
        argv0, argv0, argv0, argv0, argv0, argv0, argv0, argv0);
}

static int run_dump(const std::string& dll_path) {
    LocalReader lr(dll_path);
    VMMeta vm(&lr);
    std::printf("## source: %s\n", dll_path.c_str());
    std::printf("## counts: types=%zu structs=%zu int_consts=%zu long_consts=%zu\n",
                vm.num_types(), vm.num_structs(),
                vm.num_int_consts(), vm.num_long_consts());
    return 0;
}

static int run_threads(DWORD pid) {
    RemoteReader rr(pid);
    VMMeta vm(&rr);
    ThreadWalker tw(&vm);
    auto threads = tw.list();
    std::printf("[pid=%lu] strategy=%s  %zu threads\n",
                (unsigned long)pid, tw.strategy().c_str(), threads.size());
    for (auto& t : threads) {
        std::printf("  JavaThread@%016llx  tid=%u  %s  thrObj=%llx  vthread=%llx\n",
                    (unsigned long long)t.address, t.os_tid,
                    t.state_name.c_str(),
                    (unsigned long long)t.thread_obj,
                    (unsigned long long)t.vthread);
    }
    return 0;
}

static int run_classes(DWORD pid) {
    RemoteReader rr(pid);
    VMMeta vm(&rr);
    ClassWalker cw(&vm);
    auto classes = cw.list();
    std::printf("[pid=%lu] strategy=%s  %zu classes\n",
                (unsigned long)pid, cw.strategy().c_str(), classes.size());
    size_t shown = 0;
    for (auto& k : classes) {
        if (k.kind == "instance" && k.name.rfind("java/lang/", 0) == 0) {
            std::printf("  %s  @ %llx  (%s)\n", k.name.c_str(),
                        (unsigned long long)k.address, k.kind.c_str());
            if (++shown >= 10) break;
        }
    }
    return 0;
}

static int run_read_string(DWORD pid, const std::string& klass_name,
                             const std::string& field_name) {
    RemoteReader rr(pid);
    VMMeta vm(&rr);
    OopDecoder dec(&vm);
    ZGCDecoder zgc = ZGCDecoder::detect(&vm);
    StringReader sr(&vm, &dec, &zgc);

    ClassWalker cw(&vm);
    uint64_t klass = 0;
    for (auto& k : cw.list()) {
        if (k.name == klass_name) { klass = k.address; break; }
    }
    if (!klass) {
        std::fprintf(stderr, "class not found: %s\n", klass_name.c_str());
        return 3;
    }
    auto mf = vm.type("Klass")->field("_java_mirror");
    uint64_t handle = rr.read_u64(klass + mf->offset);
    uint64_t mirror = mf->type_string == "OopHandle" ? rr.read_u64(handle) : handle;
    // Under ZGC the mirror slot holds a coloured pointer — uncolour before
    // adding field offsets.
    if (zgc.is_active()) mirror = zgc.decode(mirror);

    auto fr = find_field(&vm, klass, field_name);
    if (!fr) {
        std::fprintf(stderr, "field not found: %s.%s\n",
                     klass_name.c_str(), field_name.c_str());
        return 3;
    }

    uint64_t slot = mirror + fr->offset;
    uint64_t oop;
    if (zgc.is_active()) {
        oop = zgc.decode(rr.read_u64(slot));
    } else if (dec.oops_are_compressed()) {
        oop = dec.decode_oop(rr.read_u32(slot));
    } else {
        oop = rr.read_u64(slot);
    }

    std::string text = sr.read(oop);
    std::printf("[pid=%lu] %s.%s = %s\n",
                (unsigned long)pid, klass_name.c_str(),
                field_name.c_str(), text.c_str());
    return 0;
}

// Overwrite a static reference-typed field on `klass_name.field_name` with
// the value currently held by `klass_name.donor_field`. Exercises the full
// write path: encode_oop/zgc.encode_for_store + card-mark.
static int run_write_ref(DWORD pid,
                          const std::string& klass_name,
                          const std::string& field_name,
                          const std::string& donor_field) {
    RemoteReader rr(pid);
    VMMeta vm(&rr);
    OopDecoder dec(&vm);
    ZGCDecoder zgc = ZGCDecoder::detect(&vm);

    ClassWalker cw(&vm);
    uint64_t klass = 0;
    for (auto& k : cw.list()) {
        if (k.name == klass_name) { klass = k.address; break; }
    }
    if (!klass) {
        std::fprintf(stderr, "class not found: %s\n", klass_name.c_str());
        return 3;
    }
    auto mf = vm.type("Klass")->field("_java_mirror");
    uint64_t handle = rr.read_u64(klass + mf->offset);
    uint64_t mirror = mf->type_string == "OopHandle" ? rr.read_u64(handle) : handle;
    if (zgc.is_active()) mirror = zgc.decode(mirror);

    auto dst = find_field(&vm, klass, field_name);
    auto src = find_field(&vm, klass, donor_field);
    if (!dst || !src) {
        std::fprintf(stderr, "field missing: need %s + %s\n",
                     field_name.c_str(), donor_field.c_str());
        return 3;
    }
    uint64_t dst_slot = mirror + dst->offset;
    uint64_t src_slot = mirror + src->offset;

    if (zgc.is_active()) {
        // Read donor raw coloured pointer, re-colour for the store, write 8B.
        uint64_t src_raw = rr.read_u64(src_slot);
        uint64_t src_heap = zgc.decode(src_raw);
        uint64_t coloured = zgc.encode_for_store(src_heap);
        rr.write(dst_slot, &coloured, 8);
    } else if (dec.oops_are_compressed()) {
        uint32_t narrow = rr.read_u32(src_slot);
        rr.write(dst_slot, &narrow, 4);
        uint64_t byte_map = get_card_byte_map_base(&vm);
        mark_card_dirty(&vm, byte_map, dst_slot);
    } else {
        uint64_t wide = rr.read_u64(src_slot);
        rr.write(dst_slot, &wide, 8);
        uint64_t byte_map = get_card_byte_map_base(&vm);
        mark_card_dirty(&vm, byte_map, dst_slot);
    }
    std::printf("[pid=%lu] %s.%s := %s.%s  ok\n",
                (unsigned long)pid, klass_name.c_str(), field_name.c_str(),
                klass_name.c_str(), donor_field.c_str());
    return 0;
}

static int run_instances(DWORD pid, const std::string& klass_name) {
    RemoteReader rr(pid);
    VMMeta vm(&rr);
    OopDecoder dec(&vm);
    ClassWalker cw(&vm);
    uint64_t klass = 0;
    for (auto& k : cw.list()) {
        if (k.name == klass_name) { klass = k.address; break; }
    }
    if (!klass) {
        std::fprintf(stderr, "class not found: %s\n", klass_name.c_str());
        return 3;
    }
    auto found = find_instances_by_klass(&vm, &dec, klass);
    std::printf("[pid=%lu] %s: %zu instances found\n",
                (unsigned long)pid, klass_name.c_str(), found.size());
    size_t show = std::min<size_t>(found.size(), 16);
    for (size_t i = 0; i < show; ++i)
        std::printf("  oop @ %llx\n", (unsigned long long)found[i]);
    return 0;
}

static int run_methods(DWORD pid, const std::string& klass_name) {
    RemoteReader rr(pid);
    VMMeta vm(&rr);
    ClassWalker cw(&vm);
    uint64_t klass = 0;
    for (auto& k : cw.list()) {
        if (k.name == klass_name) { klass = k.address; break; }
    }
    if (!klass) { std::fprintf(stderr, "class not found: %s\n", klass_name.c_str()); return 3; }
    auto ms = methods_of(&vm, klass);
    std::printf("[pid=%lu] %s: %zu methods\n",
                (unsigned long)pid, klass_name.c_str(), ms.size());
    for (auto& m : ms) {
        std::printf("  Method@%016llx  %s%s  code_size=%u\n",
                    (unsigned long long)m.address,
                    m.name.c_str(), m.signature.c_str(), m.code_size);
    }
    return 0;
}

static int run_mute(DWORD pid, const std::string& klass_name,
                     const std::string& method_name) {
    RemoteReader rr(pid);
    VMMeta vm(&rr);
    ClassWalker cw(&vm);
    uint64_t klass = 0;
    for (auto& k : cw.list()) {
        if (k.name == klass_name) { klass = k.address; break; }
    }
    if (!klass) { std::fprintf(stderr, "class not found: %s\n", klass_name.c_str()); return 3; }
    auto m = find_method(&vm, klass, method_name);
    if (!m) { std::fprintf(stderr, "method not found: %s.%s\n",
                            klass_name.c_str(), method_name.c_str()); return 3; }
    if (m->signature.back() != 'V') {
        std::fprintf(stderr, "cannot mute non-void method %s%s\n",
                     m->name.c_str(), m->signature.c_str());
        return 3;
    }
    rewrite_method_body(&vm, *m, make_nop_return());
    std::printf("[pid=%lu] %s.%s%s muted (body = return)\n",
                (unsigned long)pid, klass_name.c_str(),
                m->name.c_str(), m->signature.c_str());
    return 0;
}

static int run_alloc_ba(DWORD pid, int length) {
    RemoteReader rr(pid);
    VMMeta vm(&rr);
    OopDecoder dec(&vm);
    ZGCDecoder zgc = ZGCDecoder::detect(&vm);
    TLABAllocator alloc(&vm, &dec, &zgc);
    // Find [B (byte array) klass via Universe::_byteArrayKlassObj.
    uint64_t ba_klass = 0;
    if (vm.has_type("Universe") && vm.type("Universe")->has_field("_byteArrayKlassObj")) {
        ba_klass = rr.read_u64(vm.type("Universe")->field("_byteArrayKlassObj")->address);
    }
    if (!ba_klass) {
        ClassWalker cw(&vm);
        for (auto& k : cw.list()) if (k.name == "[B") { ba_klass = k.address; break; }
    }
    if (!ba_klass) { std::fprintf(stderr, "[B klass not found\n"); return 3; }
    uint64_t oop = alloc.allocate_type_array(ba_klass, length);
    std::printf("[pid=%lu] byte[%d] @ %llx  data_off=%zu\n",
                (unsigned long)pid, length, (unsigned long long)oop,
                alloc.array_data_offset());
    return 0;
}

static int run_hook(DWORD pid, const std::string& klass_name,
                    const std::string& method_name) {
    RemoteReader rr(pid);
    VMMeta vm(&rr);
    ClassWalker cw(&vm);
    uint64_t klass = 0;
    for (auto& k : cw.list()) {
        if (k.name == klass_name) { klass = k.address; break; }
    }
    if (!klass) { std::fprintf(stderr, "class not found: %s\n", klass_name.c_str()); return 3; }
    auto m = find_method(&vm, klass, method_name);
    if (!m) { std::fprintf(stderr, "method not found\n"); return 3; }

    auto hook = install_counting_hook(&vm, *m);
    std::printf("[pid=%lu] hook installed on %s.%s (trampoline=%llx, counter=%llx)\n",
                (unsigned long)pid, klass_name.c_str(), m->name.c_str(),
                (unsigned long long)hook.trampoline_addr,
                (unsigned long long)hook.counter_addr);
    std::this_thread::sleep_for(std::chrono::seconds(2));
    std::printf("[pid=%lu] hook count after 2s = %llu\n",
                (unsigned long)pid, (unsigned long long)hook.read_count());
    hook.uninstall();
    return 0;
}

static int run_inject(DWORD pid, const std::string& dll_path) {
    uint32_t hmodule = inject_dll(pid, dll_path);
    std::printf("[pid=%lu] LoadLibraryA -> HMODULE low32 = 0x%08x\n",
                (unsigned long)pid, hmodule);
    return hmodule ? 0 : 4;
}

static int run_hw_watch(DWORD pid, uint64_t addr, int slot) {
    int ok = set_hw_watchpoint(pid, addr, /*length*/4, slot, /*write_only*/true);
    std::printf("[pid=%lu] armed DR%d on 0x%llx across %d threads\n",
                (unsigned long)pid, slot, (unsigned long long)addr, ok);
    return ok ? 0 : 4;
}

static int run_clone_class(DWORD pid, const std::string& donor,
                            const std::string& new_name) {
    RemoteReader rr(pid);
    VMMeta vm(&rr);
    ClassWalker cw(&vm);
    uint64_t donor_klass = 0;
    for (auto& k : cw.list()) {
        if (k.name == donor) { donor_klass = k.address; break; }
    }
    if (!donor_klass) {
        std::fprintf(stderr, "donor not found: %s\n", donor.c_str());
        return 3;
    }
    auto c = clone_klass(&vm, donor_klass, new_name);
    std::printf("[pid=%lu] cloned %s@%llx -> %s@%llx (symbol @%llx)\n",
                (unsigned long)pid, donor.c_str(),
                (unsigned long long)donor_klass, new_name.c_str(),
                (unsigned long long)c.clone_addr,
                (unsigned long long)c.new_symbol);
    // Verify via a fresh walker over the same target.
    ClassWalker cw2(&vm);
    bool found = false;
    for (auto& k : cw2.list()) {
        if (k.name == new_name) { found = true; break; }
    }
    std::printf("  ClassWalker sees %s? %s\n", new_name.c_str(),
                found ? "YES" : "NO");
    // Revert so the target shuts down cleanly.
    unclone_klass(&vm, c);
    return found ? 0 : 4;
}

static int run_clone_class_l2(DWORD pid, const std::string& donor,
                                const std::string& new_name) {
    RemoteReader rr(pid);
    VMMeta vm(&rr);
    ClassWalker cw(&vm);
    uint64_t donor_klass = 0;
    for (auto& k : cw.list()) {
        if (k.name == donor) { donor_klass = k.address; break; }
    }
    if (!donor_klass) {
        std::fprintf(stderr, "donor not found: %s\n", donor.c_str());
        return 3;
    }
    // Patch: overwrite byte 0 of tick() with 0x00 (nop). Harmless
    // inspection-wise, preserves code_size, shows clone has independent
    // storage.
    auto patch = [](const std::string& name, std::vector<uint8_t>& bc) {
        if (name == "tick" && !bc.empty()) bc[0] = 0x00;
    };
    auto d = clone_klass_deep(&vm, donor_klass, new_name, patch);
    std::printf("[pid=%lu] deep-cloned %s -> %s (%zu methods)\n",
                (unsigned long)pid, donor.c_str(), new_name.c_str(),
                d.new_methods.size());
    // Verify: dump bytecode of both tick() methods, compare.
    auto donor_tick = find_method(&vm, donor_klass, "tick");
    uint64_t clone_klass_addr = d.base.clone_addr;
    auto clone_tick = find_method(&vm, clone_klass_addr, "tick");
    if (donor_tick && clone_tick) {
        auto a = rr.read(donor_tick->code_base, donor_tick->code_size);
        auto b = rr.read(clone_tick->code_base, clone_tick->code_size);
        bool differ = a != b;
        std::printf("  donor  tick[0..3] = %02x %02x %02x %02x\n",
                    a[0], a[1], a[2], a[3]);
        std::printf("  clone  tick[0..3] = %02x %02x %02x %02x  %s\n",
                    b[0], b[1], b[2], b[3], differ ? "(differs OK)" : "(identical!)");
        unclone_klass_deep(&vm, d);
        return differ ? 0 : 4;
    }
    unclone_klass_deep(&vm, d);
    return 3;
}

static int run_dump_bytecode(DWORD pid, const std::string& klass_name,
                              const std::string& method_name) {
    RemoteReader rr(pid);
    VMMeta vm(&rr);
    ClassWalker cw(&vm);
    uint64_t klass = 0;
    for (auto& k : cw.list()) {
        if (k.name == klass_name) { klass = k.address; break; }
    }
    if (!klass) { std::fprintf(stderr, "class not found\n"); return 3; }
    auto m = find_method(&vm, klass, method_name);
    if (!m) { std::fprintf(stderr, "method not found\n"); return 3; }
    auto bc = rr.read(m->code_base, m->code_size);
    std::printf("[pid=%lu] %s.%s%s  code_size=%u\n  ",
                (unsigned long)pid, klass_name.c_str(),
                m->name.c_str(), m->signature.c_str(), m->code_size);
    for (size_t i = 0; i < bc.size(); ++i) {
        std::printf("%02x", bc[i]);
        if ((i & 15) == 15 && i + 1 < bc.size()) std::printf("\n  ");
        else if (i + 1 < bc.size()) std::printf(" ");
    }
    std::printf("\n");
    return 0;
}

static int run_clone_class_l3(DWORD pid, const std::string& donor,
                                const std::string& new_name) {
    RemoteReader rr(pid);
    VMMeta vm(&rr);
    ClassWalker cw(&vm);
    uint64_t donor_klass = 0;
    for (auto& k : cw.list()) {
        if (k.name == donor) { donor_klass = k.address; break; }
    }
    if (!donor_klass) {
        std::fprintf(stderr, "donor not found: %s\n", donor.c_str());
        return 3;
    }
    SysDictCloneResult res;
    try {
        res = clone_and_register_in_sysdict(&vm, donor_klass, new_name);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "L3 register failed: %s\n", e.what());
        return 3;
    }
    std::printf("[pid=%lu] L3 cloned %s -> %s\n",
                (unsigned long)pid, donor.c_str(), new_name.c_str());
    std::printf("  klass=%llx  symbol=%llx\n",
                (unsigned long long)res.base.clone_addr,
                (unsigned long long)res.base.new_symbol);
    std::printf("  dict=%llx  bucket[%d]  hash=%08x  entry=%llx\n",
                (unsigned long long)res.dictionary, res.bucket_index,
                res.hash, (unsigned long long)res.new_entry);

    // Verify by walking the bucket chain.
    auto lay = discover_dict_layout(&vm);
    bool found = false;
    if (lay.has_value()) {
        size_t lit_off = lay->entry_literal_off;
        size_t nxt_off = lay->entry_next_off;
        size_t esz = lay->entry_size;
        uint64_t e = rr.read_u64(res.bucket_addr);
        for (int i = 0; i < 32 && e != 0; ++i) {
            auto eb = rr.read(e, esz);
            uint64_t lit = 0, nx = 0;
            for (size_t k = 0; k < 8; ++k) {
                lit |= (uint64_t(eb[lit_off + k]) << (k * 8));
                nx  |= (uint64_t(eb[nxt_off + k]) << (k * 8));
            }
            if (lit == res.base.clone_addr) { found = true; break; }
            e = nx;
        }
    }
    std::printf("  bucket walk finds clone? %s\n", found ? "YES" : "NO");
    // Clean up so the target shuts down cleanly. Note: `bucket walk finds`
    // confirms insert, but HotSpot's Class.forName actually routes
    // through a different table (placeholder/shared_dictionary depending
    // on loader), so end-to-end Class.forName reachability isn't claimed.
    unregister_from_sysdict(&vm, res);
    return found ? 0 : 4;
}

static int run_replace_class(DWORD pid, const std::string& donor) {
    RemoteReader rr(pid);
    VMMeta vm(&rr);
    ClassWalker cw(&vm);
    uint64_t donor_klass = 0;
    for (auto& k : cw.list()) {
        if (k.name == donor) { donor_klass = k.address; break; }
    }
    if (!donor_klass) { std::fprintf(stderr, "donor not found\n"); return 3; }
    ReplaceClassResult res;
    try {
        res = replace_class_in_sysdict(&vm, donor_klass);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "replace failed: %s\n", e.what());
        return 3;
    }
    std::printf("[pid=%lu] replaced Class.forName(\"%s\") target:\n",
                (unsigned long)pid, donor.c_str());
    std::printf("  donor_klass=%llx  clone=%llx\n",
                (unsigned long long)donor_klass,
                (unsigned long long)res.base.clone_addr);
    std::printf("  bucket[%d] (hash=%08x) reused from donor's entry\n",
                res.bucket_index, res.hash_reused);
    std::printf("  Class.forName lookup walks bucket head-first -> our entry\n");
    // Don't unreplace; leave installed so caller can probe externally.
    return 0;
}

static int run_replace_class_hook(DWORD pid, const std::string& donor) {
    RemoteReader rr(pid);
    VMMeta vm(&rr);
    ClassWalker cw(&vm);
    uint64_t donor_klass = 0;
    for (auto& k : cw.list()) {
        if (k.name == donor) { donor_klass = k.address; break; }
    }
    if (!donor_klass) { std::fprintf(stderr, "donor not found\n"); return 3; }

    // 1. Clone Klass + CLDG insertion (L1).
    auto clone = clone_klass(&vm, donor_klass, donor);  // reuse same name for mirror

    // 2. Allocate a fresh java.lang.Class mirror pointing at the clone
    //    (same trick as replace-class).
    uint64_t class_klass = 0;
    for (auto& k : cw.list()) if (k.name == "java/lang/Class") { class_klass = k.address; break; }
    if (!class_klass) {
        std::fprintf(stderr, "java/lang/Class not found\n");
        unclone_klass(&vm, clone);
        return 3;
    }
    OopDecoder dec(&vm);
    ZGCDecoder zgc = ZGCDecoder::detect(&vm);
    TLABAllocator alloc(&vm, &dec, &zgc);
    uint64_t new_mirror = alloc.allocate_instance(class_klass);

    auto* klass_t_ptr = vm.type("Klass");
    auto* mf = klass_t_ptr->field("_java_mirror");
    uint64_t donor_handle = rr.read_u64(donor_klass + mf->offset);
    uint64_t donor_mirror = mf->type_string == "OopHandle"
        ? rr.read_u64(donor_handle) : donor_handle;
    if (zgc.is_active()) donor_mirror = zgc.decode(donor_mirror);
    int32_t class_lh = rr.read_i32(class_klass
        + klass_t_ptr->field("_layout_helper")->offset);
    size_t mirror_size = size_t(class_lh) & ~size_t(0x7);
    size_t copy_from = dec.compressed_klass() ? 12 : 16;
    auto mirror_bytes = rr.read(donor_mirror + copy_from, mirror_size - copy_from);
    rr.write(new_mirror + copy_from, mirror_bytes.data(), mirror_bytes.size());
    const TypeInfo* jlc = vm.type("java_lang_Class");
    int32_t klass_off = rr.read_i32(jlc->field("_klass_offset")->address);
    uint64_t clone_ptr = clone.clone_addr;
    rr.write(new_mirror + klass_off, &clone_ptr, 8);

    // 3. Install the wrapper hook. It calls original (so caller gets a
    //    valid JNI local ref), then post-processes the handle by
    //    swapping donor's mirror oop for our clone's mirror oop.
    SysDictHook hk;
    try {
        hk = install_sysdict_hook_full(&vm, donor, donor_mirror, new_mirror);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "hook install failed: %s\n", e.what());
        unclone_klass(&vm, clone);
        return 3;
    }
    std::printf("[pid=%lu] hook installed on JVM_FindClassFromCaller@%llx\n"
                "  hook_page=%llx  tramp_page=%llx  prologue_len=%zu\n"
                "  fake_handle_slot=%llx -> new_mirror=%llx (clone klass=%llx)\n",
                (unsigned long)pid,
                (unsigned long long)hk.original_fn,
                (unsigned long long)hk.hook_page,
                (unsigned long long)hk.trampoline_page,
                hk.prologue_len,
                (unsigned long long)hk.fake_handle_slot,
                (unsigned long long)hk.clone_mirror,
                (unsigned long long)clone.clone_addr);
    // Leave installed so caller can probe externally.
    return 0;
}

// Open the agent's shared memory channel for a given pid.
static marrow::AgentIpcBlock* open_agent_ipc(DWORD pid, HANDLE* map_out)
{
    char name[128];
    _snprintf_s(name, sizeof(name), _TRUNCATE,
                "Local\\marrow-agent-%lu", (unsigned long)pid);
    HANDLE h = OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE, FALSE, name);
    if (!h) return nullptr;
    auto* b = static_cast<marrow::AgentIpcBlock*>(
        MapViewOfFile(h, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0,
                       marrow::AGENT_IPC_SIZE));
    if (!b || b->magic != marrow::AGENT_IPC_MAGIC) {
        if (b) UnmapViewOfFile(b);
        CloseHandle(h);
        return nullptr;
    }
    *map_out = h;
    return b;
}

static int run_agent_send(DWORD pid, const std::string& cmd,
                           const std::vector<std::string>& args)
{
    HANDLE h = nullptr;
    auto* b = open_agent_ipc(pid, &h);
    if (!b) { std::fprintf(stderr, "agent not attached to pid %lu\n", pid); return 3; }

    // Assemble request: cmd id + args + msg buffer.
    using CId = marrow::CommandId;
    CId cid = CId::Ping;
    std::string msg_blob;
    std::vector<uint64_t> argvals;
    if      (cmd == "ping")      cid = CId::Ping;
    else if (cmd == "findclass") { cid = CId::FindClass; msg_blob = args[0]; }
    else if (cmd == "hookmethod") {
        cid = CId::HookMethod;
        argvals.push_back(std::stoull(args[0], nullptr, 0)); // klass ptr
        argvals.push_back(0); // msg offset placeholder
        argvals.push_back(std::stoull(args[2], nullptr, 0)); // cookie
        msg_blob = args[1];
    }
    else if (cmd == "hookcount") {
        cid = CId::ReadHookCount;
        argvals.push_back(std::stoull(args[0], nullptr, 0));
    }
    else if (cmd == "eval") { cid = CId::Eval; msg_blob = args[0]; }
    else if (cmd == "shutdown") cid = CId::Shutdown;
    else { std::fprintf(stderr, "unknown command %s\n", cmd.c_str()); return 3; }

    // Fill block fields.
    b->cmd = uint32_t(cid);
    b->arg_count = uint32_t(argvals.size());
    for (size_t i = 0; i < argvals.size() && i < 16; ++i) b->args[i] = argvals[i];
    if (!msg_blob.empty()) {
        size_t n = std::min(msg_blob.size(), marrow::AGENT_IPC_MSG_MAX - 1);
        std::memcpy(b->msg, msg_blob.data(), n);
        b->msg[n] = 0;
    }
    b->request_id++;
    b->state = uint32_t(marrow::IpcState::Request);

    // Wait for reply (bounded spin).
    auto start = std::chrono::steady_clock::now();
    while (b->state != uint32_t(marrow::IpcState::Reply)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        if (std::chrono::steady_clock::now() - start > std::chrono::seconds(30)) {
            std::fprintf(stderr, "timeout waiting for agent reply\n");
            UnmapViewOfFile(b); CloseHandle(h);
            return 4;
        }
    }
    std::printf("[agent.reply] status=%u", b->status);
    for (uint32_t i = 0; i < 16 && b->result[i]; ++i)
        std::printf("  result[%u]=%llx", i, (unsigned long long)b->result[i]);
    if (b->msg_len) std::printf("  msg=%.*s", b->msg_len, b->msg);
    std::printf("\n");
    // Reset to idle so next request can be submitted.
    b->state = uint32_t(marrow::IpcState::Idle);
    UnmapViewOfFile(b); CloseHandle(h);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 3) { usage(argv[0]); return 1; }
    try {
        std::string cmd = argv[1];
        if      (cmd == "dump")    return run_dump(argv[2]);
        else if (cmd == "threads") return run_threads(DWORD(std::atoi(argv[2])));
        else if (cmd == "classes") return run_classes(DWORD(std::atoi(argv[2])));
        else if (cmd == "read-string" && argc >= 5)
            return run_read_string(DWORD(std::atoi(argv[2])), argv[3], argv[4]);
        else if (cmd == "instances" && argc >= 4)
            return run_instances(DWORD(std::atoi(argv[2])), argv[3]);
        else if (cmd == "write-ref" && argc >= 6)
            return run_write_ref(DWORD(std::atoi(argv[2])),
                                 argv[3], argv[4], argv[5]);
        else if (cmd == "methods" && argc >= 4)
            return run_methods(DWORD(std::atoi(argv[2])), argv[3]);
        else if (cmd == "mute" && argc >= 5)
            return run_mute(DWORD(std::atoi(argv[2])), argv[3], argv[4]);
        else if (cmd == "alloc-ba" && argc >= 4)
            return run_alloc_ba(DWORD(std::atoi(argv[2])), std::atoi(argv[3]));
        else if (cmd == "hook" && argc >= 5)
            return run_hook(DWORD(std::atoi(argv[2])), argv[3], argv[4]);
        else if (cmd == "inject" && argc >= 4)
            return run_inject(DWORD(std::atoi(argv[2])), argv[3]);
        else if (cmd == "hw-watch" && argc >= 4) {
            int slot = (argc >= 5) ? std::atoi(argv[4]) : 0;
            return run_hw_watch(DWORD(std::atoi(argv[2])),
                                strtoull(argv[3], nullptr, 0), slot);
        }
        else if (cmd == "clone-class" && argc >= 5)
            return run_clone_class(DWORD(std::atoi(argv[2])), argv[3], argv[4]);
        else if (cmd == "clone-class-l2" && argc >= 5)
            return run_clone_class_l2(DWORD(std::atoi(argv[2])), argv[3], argv[4]);
        else if (cmd == "dump-bytecode" && argc >= 5)
            return run_dump_bytecode(DWORD(std::atoi(argv[2])), argv[3], argv[4]);
        else if (cmd == "clone-class-l3" && argc >= 5)
            return run_clone_class_l3(DWORD(std::atoi(argv[2])), argv[3], argv[4]);
        else if (cmd == "replace-class" && argc >= 4)
            return run_replace_class(DWORD(std::atoi(argv[2])), argv[3]);
        else if (cmd == "replace-class-hook" && argc >= 4)
            return run_replace_class_hook(DWORD(std::atoi(argv[2])), argv[3]);
        else if (cmd == "agent" && argc >= 4) {
            DWORD pid = DWORD(std::atoi(argv[2]));
            std::string sub = argv[3];
            std::vector<std::string> a;
            for (int i = 4; i < argc; ++i) a.push_back(argv[i]);
            return run_agent_send(pid, sub, a);
        }
        else if (cmd == "hook-passthrough" && argc >= 3) {
            RemoteReader rr(DWORD(std::atoi(argv[2])));
            VMMeta vm(&rr);
            auto h = install_sysdict_hook_passthrough(&vm);
            std::printf("[pid=%s] passthrough hook installed  orig=%llx  "
                        "tramp=%llx  hook=%llx  N=%zu\n",
                        argv[2], (unsigned long long)h.original_fn,
                        (unsigned long long)h.trampoline_page,
                        (unsigned long long)h.hook_page, h.prologue_len);
            return 0;
        }
        usage(argv[0]);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "ERROR: %s\n", e.what());
        return 2;
    }
    return 1;
}
