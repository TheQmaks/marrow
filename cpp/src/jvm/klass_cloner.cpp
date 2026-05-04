#include "klass_cloner.hpp"
#include "method_walker.hpp"
#include "dict_analyzer.hpp"
#include "tlab.hpp"
#include "walker.hpp"
#include <cstring>
#include <stdexcept>
#include <vector>
#include <unordered_set>

namespace marrow {

static size_t page_align(size_t n) { return (n + 0xFFF) & ~size_t(0xFFF); }

uint64_t alloc_symbol(VMMeta* vm, const std::string& name)
{
    const TypeInfo* sym_t = vm->type("Symbol");
    if (!sym_t || !sym_t->has_field("_length") || !sym_t->has_field("_body"))
        throw std::runtime_error("Symbol type layout incomplete");
    Reader* r = vm->reader();
    size_t body_off = sym_t->field("_body")->offset;
    size_t length = name.size();
    size_t total = body_off + length;
    size_t page = page_align(total);
    uint64_t addr = r->alloc(page, /*exec*/false);

    std::vector<uint8_t> buf(page, 0);
    uint16_t u16len = uint16_t(length);
    std::memcpy(buf.data() + sym_t->field("_length")->offset, &u16len, 2);
    // Mark refcount permanent (-1) under whichever layout this JDK uses.
    if (sym_t->has_field("_refcount")) {
        int16_t rc = -1;
        std::memcpy(buf.data() + sym_t->field("_refcount")->offset, &rc, 2);
    }
    if (sym_t->has_field("_hash_and_refcount")) {
        uint32_t packed = 0xFFFFFFFFu;
        std::memcpy(buf.data() + sym_t->field("_hash_and_refcount")->offset,
                    &packed, 4);
    }
    if (sym_t->has_field("_identity_hash")) {
        int32_t h = 0;
        std::memcpy(buf.data() + sym_t->field("_identity_hash")->offset, &h, 4);
    }
    std::memcpy(buf.data() + body_off, name.data(), length);
    r->write(addr, buf.data(), buf.size());
    return addr;
}

ClonedKlass clone_klass(VMMeta* vm, uint64_t donor, const std::string& new_name)
{
    const TypeInfo* ik = vm->type("InstanceKlass");
    const TypeInfo* klass_t = vm->type("Klass");
    const TypeInfo* cld_t = vm->type("ClassLoaderData");
    if (!ik || !klass_t || !cld_t)
        throw std::runtime_error("InstanceKlass/Klass/ClassLoaderData missing");
    Reader* r = vm->reader();

    size_t ik_size = size_t(ik->size);
    size_t name_off = klass_t->field("_name")->offset;
    size_t next_link_off = klass_t->field("_next_link")->offset;
    size_t cld_off = klass_t->field("_class_loader_data")->offset;
    size_t cld_klasses_off = cld_t->field("_klasses")->offset;

    // 1. Alloc + copy klass bytes.
    uint64_t clone = r->alloc(page_align(ik_size), /*exec*/false);
    auto klass_bytes = r->read(donor, ik_size);
    r->write(clone, klass_bytes.data(), klass_bytes.size());

    // 2. Alloc fresh Symbol for the new name and point _name at it.
    uint64_t new_sym = alloc_symbol(vm, new_name);
    uint64_t sym_ptr = new_sym;
    r->write(clone + name_off, &sym_ptr, 8);

    // 3. Splice clone at head of the donor's owning CLD klass list.
    uint64_t cld = r->read_u64(donor + cld_off);
    if (!cld) throw std::runtime_error("donor Klass has no CLD");
    uint64_t old_head = r->read_u64(cld + cld_klasses_off);
    uint64_t head_val = old_head;
    r->write(clone + next_link_off, &head_val, 8);
    uint64_t new_head = clone;
    r->write(cld + cld_klasses_off, &new_head, 8);

    return {clone, new_sym, donor, cld, old_head};
}

void unclone_klass(VMMeta* vm, const ClonedKlass& c)
{
    const TypeInfo* cld_t = vm->type("ClassLoaderData");
    size_t cld_klasses_off = cld_t->field("_klasses")->offset;
    uint64_t v = c.old_head;
    vm->reader()->write(c.cld_addr + cld_klasses_off, &v, 8);
    vm->reader()->free(c.clone_addr);
    vm->reader()->free(c.new_symbol);
}

// --- Level 2 deep clone ---------------------------------------------------

DeepClonedKlass clone_klass_deep(VMMeta* vm, uint64_t donor_klass,
                                  const std::string& new_name,
                                  BytecodePatch patch)
{
    // 1. Shallow clone first; gives us a registered Klass page we can then
    // retarget at fresh methods storage.
    ClonedKlass base = clone_klass(vm, donor_klass, new_name);

    const TypeInfo* ik = vm->type("InstanceKlass");
    const TypeInfo* mt = vm->type("Method");
    const TypeInfo* cmt = vm->type("ConstMethod");
    if (!ik || !mt || !cmt)
        throw std::runtime_error("InstanceKlass/Method/ConstMethod missing");
    Reader* r = vm->reader();

    size_t methods_off = ik->field("_methods")->offset;
    size_t off_constmethod = mt->field("_constMethod")->offset;
    size_t cm_header_size  = cmt->size;
    size_t m_size          = mt->size;

    // 2. Enumerate donor's Method* list and ConstMethod shapes.
    auto donor_methods = methods_of(vm, donor_klass);

    // 3. Allocate a fresh Array<Method*> with the same length.
    size_t n = donor_methods.size();
    size_t arr_size = 8 /* Array header: int _length + pad */ + n * 8;
    uint64_t new_arr = r->alloc(page_align(arr_size), /*exec*/false);
    int32_t n32 = int32_t(n);
    r->write(new_arr, &n32, 4);

    DeepClonedKlass d;
    d.base = base;
    d.new_methods_array = new_arr;
    d.new_methods.reserve(n);
    d.new_const_methods.reserve(n);

    for (size_t i = 0; i < n; ++i) {
        const MethodSnapshot& ms = donor_methods[i];
        size_t total_cm = cm_header_size + ms.code_size;
        uint64_t new_cm = r->alloc(page_align(total_cm), /*exec*/false);
        auto cm_bytes = r->read(ms.const_method, total_cm);
        // Optional bytecode patch in-place.
        if (patch) {
            std::vector<uint8_t> bc(cm_bytes.begin() + cm_header_size,
                                     cm_bytes.end());
            patch(ms.name, bc);
            // Preserve code_size — patch may only rewrite inside existing slot.
            if (bc.size() != ms.code_size)
                throw std::runtime_error(
                    "bytecode patch changed length; not supported");
            std::copy(bc.begin(), bc.end(), cm_bytes.begin() + cm_header_size);
        }
        r->write(new_cm, cm_bytes.data(), cm_bytes.size());

        // Clone Method header; retarget its _constMethod at our copy.
        uint64_t new_m = r->alloc(page_align(m_size), /*exec*/false);
        auto m_bytes = r->read(ms.address, m_size);
        r->write(new_m, m_bytes.data(), m_bytes.size());
        uint64_t cm_ptr = new_cm;
        r->write(new_m + off_constmethod, &cm_ptr, 8);

        // Store pointer in our new array.
        uint64_t m_ptr = new_m;
        r->write(new_arr + 8 + i * 8, &m_ptr, 8);

        d.new_methods.push_back(new_m);
        d.new_const_methods.push_back(new_cm);
    }

    // 4. Redirect the cloned Klass to our _methods array.
    uint64_t arr_ptr = new_arr;
    r->write(base.clone_addr + methods_off, &arr_ptr, 8);

    return d;
}

void unclone_klass_deep(VMMeta* vm, const DeepClonedKlass& d)
{
    for (uint64_t m : d.new_methods) vm->reader()->free(m);
    for (uint64_t cm : d.new_const_methods) vm->reader()->free(cm);
    vm->reader()->free(d.new_methods_array);
    unclone_klass(vm, d.base);
}

// --- Level 3: dictionary registration -----------------------------------

static uint32_t java_string_hash(const std::string& s) {
    uint32_t h = 0;
    for (uint8_t c : s) h = 31u * h + c;
    return h & 0x7FFFFFFFu;
}

SysDictCloneResult
clone_and_register_in_sysdict(VMMeta* vm, uint64_t donor_klass,
                              const std::string& new_name)
{
    if (!vm->has_type("Dictionary"))
        throw std::runtime_error(
            "Dictionary type not exported in this JDK (21+); "
            "Class.forName reachability isn't available without it");
    auto lay = discover_dict_layout(vm);
    if (!lay)
        throw std::runtime_error("dynamic Dictionary layout discovery failed");

    Reader* r = vm->reader();
    const TypeInfo* cld_t = vm->type("ClassLoaderData");
    const TypeInfo* klass_t = vm->type("Klass");
    size_t cld_off = klass_t->field("_class_loader_data")->offset;
    size_t cld_dict_off = cld_t->field("_dictionary")->offset;
    uint64_t donor_cld = r->read_u64(donor_klass + cld_off);
    if (!donor_cld) throw std::runtime_error("donor has no CLD");
    uint64_t dict = r->read_u64(donor_cld + cld_dict_off);
    if (!dict) throw std::runtime_error("CLD has no _dictionary");

    // Step 1: shallow clone (registers in CLDG._klasses).
    ClonedKlass base = clone_klass(vm, donor_klass, new_name);

    // Step 2: hash → bucket index.
    uint32_t hash = java_string_hash(new_name);
    int32_t ts = r->read_i32(dict + lay->table_size_off);
    uint64_t buckets = r->read_u64(dict + lay->buckets_off);
    int32_t idx = int32_t(hash % uint32_t(ts));
    uint64_t bucket_addr = buckets + size_t(idx) * 8;
    uint64_t old_head = r->read_u64(bucket_addr);

    // Step 3: alloc DictionaryEntry, fill, link into bucket head.
    uint64_t entry = r->alloc(page_align(lay->entry_size), false);
    std::vector<uint8_t> buf(lay->entry_size, 0);
    std::memcpy(buf.data() + lay->entry_hash_off, &hash, 4);
    std::memcpy(buf.data() + lay->entry_next_off, &old_head, 8);
    uint64_t lit = base.clone_addr;
    std::memcpy(buf.data() + lay->entry_literal_off, &lit, 8);
    r->write(entry, buf.data(), buf.size());
    r->write(bucket_addr, &entry, 8);

    return {base, dict, bucket_addr, old_head, entry, idx, hash};
}

void unregister_from_sysdict(VMMeta* vm, const SysDictCloneResult& r)
{
    // Restore bucket head, then free entry, then unclone the klass.
    vm->reader()->write(r.bucket_addr, &r.old_bucket_head, 8);
    vm->reader()->free(r.new_entry);
    unclone_klass(vm, r.base);
}

ReplaceClassResult replace_class_in_sysdict(VMMeta* vm, uint64_t donor_klass)
{
    if (!vm->has_type("Dictionary"))
        throw std::runtime_error("Dictionary type not exported; JDK 11/17 only");
    auto lay = discover_dict_layout(vm);
    if (!lay)
        throw std::runtime_error("dynamic Dictionary layout discovery failed");

    Reader* r = vm->reader();
    const TypeInfo* klass_t = vm->type("Klass");
    const TypeInfo* cld_t = vm->type("ClassLoaderData");
    size_t name_off = klass_t->field("_name")->offset;
    size_t cld_off = klass_t->field("_class_loader_data")->offset;
    size_t cld_dict_off = cld_t->field("_dictionary")->offset;
    size_t next_link_off = klass_t->field("_next_link")->offset;
    size_t cld_klasses_off = cld_t->field("_klasses")->offset;

    uint64_t donor_sym = r->read_u64(donor_klass + name_off);
    uint64_t donor_cld = r->read_u64(donor_klass + cld_off);

    // Locate the Dictionary that actually contains an entry pointing at
    // donor_klass. On JDK 11 the entry lives in a CLD different from
    // donor's `_class_loader_data` (some classes are hosted by a shadow
    // CLD belonging to the parent loader), so we scan every CLD in the
    // graph — bucket-by-bucket through its dictionary.
    uint64_t dict = 0;
    uint64_t hosting_cld = 0;
    uint32_t donor_hash = 0;
    int32_t donor_bucket_idx = -1;
    size_t clds_scanned = 0, dicts_scanned = 0;
    {
        const TypeInfo* cldg_t = vm->type("ClassLoaderDataGraph");
        uint64_t head = r->read_u64(cldg_t->field("_head")->address);
        std::unordered_set<uint64_t> seen;
        uint64_t cld_it = head;
        size_t n_off = cld_t->field("_next")->offset;
        while (cld_it && !seen.count(cld_it) && donor_bucket_idx < 0) {
            seen.insert(cld_it);
            ++clds_scanned;
            uint64_t d = 0;
            try { d = r->read_u64(cld_it + cld_dict_off); } catch (...) {}
            if (d) {
                int32_t ts = 0; uint64_t buckets = 0;
                try {
                    ts = r->read_i32(d + lay->table_size_off);
                    buckets = r->read_u64(d + lay->buckets_off);
                } catch (...) { ts = 0; }
                if (ts > 0 && ts < 100000
                    && buckets >= 0x10000000000ull
                    && buckets < 0x7FFFFFFFFFFFull) {
                    ++dicts_scanned;
                    for (int32_t i = 0; i < ts && donor_bucket_idx < 0; ++i) {
                        uint64_t e = 0;
                        try { e = r->read_u64(buckets + size_t(i) * 8); }
                        catch (...) { continue; }
                        int chain = 0;
                        while (e && chain < 64) {
                            std::vector<uint8_t> eb;
                            try { eb = r->read(e, lay->entry_size); }
                            catch (...) { break; }
                            uint64_t lit;
                            std::memcpy(&lit, eb.data() + lay->entry_literal_off, 8);
                            if (lit == donor_klass) {
                                std::memcpy(&donor_hash,
                                            eb.data() + lay->entry_hash_off, 4);
                                donor_bucket_idx = i;
                                dict = d; hosting_cld = cld_it;
                                break;
                            }
                            std::memcpy(&e, eb.data() + lay->entry_next_off, 8);
                            ++chain;
                        }
                    }
                }
            }
            uint64_t next_cld = 0;
            try { next_cld = r->read_u64(cld_it + n_off); } catch (...) {}
            cld_it = next_cld;
        }
    }
    if (donor_bucket_idx < 0) {
        std::fprintf(stderr,
            "replace-class scan: %zu CLDs, %zu dicts probed; donor not found\n",
            clds_scanned, dicts_scanned);
    }
    if (donor_bucket_idx < 0 || !dict)
        throw std::runtime_error(
            "donor klass not found in ANY CLD's Dictionary — "
            "it lives in SystemDictionary::_shared_dictionary or elsewhere");

    uint64_t cld = hosting_cld;
    int32_t ts = r->read_i32(dict + lay->table_size_off);
    (void)ts;  // just documenting; not used past this point
    uint64_t buckets = r->read_u64(dict + lay->buckets_off);

    // Clone the Klass page; REUSE donor's Symbol as `_name` so pointer
    // equality holds in Dictionary::find_entry.
    size_t ik_size = vm->type("InstanceKlass")->size;
    uint64_t clone = r->alloc(page_align(ik_size), false);
    auto klass_bytes = r->read(donor_klass, ik_size);
    r->write(clone, klass_bytes.data(), klass_bytes.size());
    r->write(clone + name_off, &donor_sym, 8);

    // Allocate a FRESH java.lang.Class mirror for the clone. Without this,
    // `Klass::java_mirror()` for donor and clone return the same Class
    // object and `Class.forName` can't be observed to switch. Steps:
    //   a) locate java.lang.Class klass
    //   b) TLAB-allocate an instance of it (zero-inited, correct header)
    //   c) copy donor's mirror bytes into it (keeps reflection fields
    //      the same) then overwrite the injected `_klass` offset to point
    //      at the clone
    //   d) VirtualAllocEx an 8-byte OopHandle slot, store the new mirror
    //      oop there, point `clone._java_mirror` at that slot
    OopDecoder dec(vm);
    uint64_t class_klass = 0;
    {
        ClassWalker cw(vm);
        for (auto& k : cw.list())
            if (k.name == "java/lang/Class") { class_klass = k.address; break; }
    }
    if (class_klass) {
        TLABAllocator alloc(vm, &dec);
        uint64_t new_mirror = alloc.allocate_instance(class_klass);

        // Copy donor mirror contents over the new mirror (preserves Java-
        // side state like cached reflection data, loader ref, module, etc.)
        auto mf = klass_t->field("_java_mirror");
        uint64_t donor_handle = r->read_u64(donor_klass + mf->offset);
        uint64_t donor_mirror = mf->type_string == "OopHandle"
            ? r->read_u64(donor_handle) : donor_handle;
        // Use java.lang.Class's instance layout_helper size as copy bound.
        int32_t class_lh = r->read_i32(class_klass
            + klass_t->field("_layout_helper")->offset);
        size_t mirror_size = size_t(class_lh) & ~size_t(0x7);
        // Copy bytes 16..mirror_size (skip mark + klass header we already set).
        size_t copy_from = dec.compressed_klass() ? 12 : 16;
        auto mirror_bytes = r->read(donor_mirror + copy_from,
                                     mirror_size - copy_from);
        r->write(new_mirror + copy_from,
                 mirror_bytes.data(), mirror_bytes.size());

        // Overwrite the injected `_klass` pointer to point at our clone.
        const TypeInfo* jlc = vm->type("java_lang_Class");
        int32_t klass_off = r->read_i32(jlc->field("_klass_offset")->address);
        uint64_t clone_ptr = clone;
        r->write(new_mirror + klass_off, &clone_ptr, 8);

        // Allocate a fake OopHandle slot: a plain 8-byte writable word
        // holding the new mirror's wide oop. Set clone's _java_mirror
        // pointer to this slot.
        uint64_t new_slot = r->alloc(0x1000, /*exec*/false);
        r->write(new_slot, &new_mirror, 8);
        r->write(clone + mf->offset, &new_slot, 8);
    }

    // Also insert clone into CLD._klasses so ClassWalker sees it (optional
    // but matches the behaviour of clone_klass).
    uint64_t old_klasses_head = r->read_u64(cld + cld_klasses_off);
    r->write(clone + next_link_off, &old_klasses_head, 8);
    uint64_t clone_as_head = clone;
    r->write(cld + cld_klasses_off, &clone_as_head, 8);

    // Build DictionaryEntry with reused hash + clone literal, link at head.
    uint64_t bucket_addr = buckets + size_t(donor_bucket_idx) * 8;
    uint64_t old_bucket_head = r->read_u64(bucket_addr);
    uint64_t new_entry = r->alloc(page_align(lay->entry_size), false);
    std::vector<uint8_t> buf(lay->entry_size, 0);
    std::memcpy(buf.data() + lay->entry_hash_off, &donor_hash, 4);
    std::memcpy(buf.data() + lay->entry_next_off, &old_bucket_head, 8);
    uint64_t lit = clone;
    std::memcpy(buf.data() + lay->entry_literal_off, &lit, 8);
    r->write(new_entry, buf.data(), buf.size());
    r->write(bucket_addr, &new_entry, 8);

    ClonedKlass base{clone, /*sym=*/0 /* reused, not ours */, donor_klass,
                      cld, old_klasses_head};
    return {base, dict, bucket_addr, old_bucket_head, new_entry,
            donor_bucket_idx, donor_hash};
}

void unreplace_class(VMMeta* vm, const ReplaceClassResult& r)
{
    const TypeInfo* cld_t = vm->type("ClassLoaderData");
    size_t cld_klasses_off = cld_t->field("_klasses")->offset;
    vm->reader()->write(r.bucket_addr, &r.old_bucket_head, 8);
    uint64_t old_kh = r.base.old_head;
    vm->reader()->write(r.base.cld_addr + cld_klasses_off, &old_kh, 8);
    vm->reader()->free(r.new_entry);
    vm->reader()->free(r.base.clone_addr);
    // symbol is donor's — DON'T free it
}

} // namespace marrow
