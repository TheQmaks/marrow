#include "walker.hpp"
#include <cstring>
#include <stdexcept>

namespace marrow {

// ---------------------------------------------------------------------------
// Symbol decoder
// ---------------------------------------------------------------------------

std::string read_symbol(VMMeta* vm, uint64_t addr) {
    if (!addr || addr < 0x10000) return "";
    auto r = vm->reader();
    auto sym_t = vm->type("Symbol");
    if (!sym_t) return "";
    auto len_f = sym_t->field("_length");
    auto body_f = sym_t->field("_body");
    if (!len_f || !body_f) return "";
    try {
        uint16_t length = r->read_u16(addr + len_f->offset);
        if (length == 0 || length > 4096) return "";
        auto bytes = r->read(addr + body_f->offset, length);
        return std::string(reinterpret_cast<const char*>(bytes.data()), length);
    } catch (...) {
        return "";
    }
}


// ---------------------------------------------------------------------------
// ThreadWalker
// ---------------------------------------------------------------------------

static const std::unordered_map<int, std::string> kFallbackStates = {
    {0, "_thread_uninitialized"}, {2, "_thread_new"},
    {3, "_thread_new_trans"},      {4, "_thread_in_native"},
    {5, "_thread_in_native_trans"},{6, "_thread_in_vm"},
    {7, "_thread_in_vm_trans"},    {8, "_thread_in_Java"},
    {9, "_thread_in_Java_trans"},  {10, "_thread_blocked"},
    {11, "_thread_blocked_trans"}, {12, "_thread_max_state"},
};

ThreadWalker::ThreadWalker(VMMeta* vm)
    : vm_(vm), r_(vm->reader()), state_names_(kFallbackStates)
{
    strategy_ = pick_strategy();
    auto jt = vm_->type("JavaThread");
    auto os = vm_->type("OSThread");
    if (!jt || !os) throw std::runtime_error("JavaThread/OSThread types missing");
    off_state_ = jt->field("_thread_state")->offset;
    off_threadobj_ = jt->field("_threadObj")->offset;
    off_osthread_tid_ = os->field("_thread_id")->offset;
    // _osthread moved from JavaThread to Thread in JDK 25.
    if (jt->has_field("_osthread"))
        off_osthread_ = jt->field("_osthread")->offset;
    else if (auto t = vm_->type("Thread"); t && t->has_field("_osthread"))
        off_osthread_ = t->field("_osthread")->offset;
    else
        off_osthread_present_ = false;
    if (jt->has_field("_vthread"))
        off_vthread_ = jt->field("_vthread")->offset;
}

std::string ThreadWalker::pick_strategy() const {
    auto thr = vm_->type("Threads");
    if (thr && thr->has_field("_thread_list")) return "legacy";
    if (vm_->has_type("ThreadsSMRSupport")) return "smr";
    throw std::runtime_error("no thread-enumeration path in this JVM");
}

std::vector<ThreadSnapshot> ThreadWalker::list() {
    std::vector<ThreadSnapshot> out;
    if (strategy_ == "legacy") walk_legacy(out);
    else                       walk_smr(out);
    return out;
}

void ThreadWalker::walk_legacy(std::vector<ThreadSnapshot>& out) {
    auto thr = vm_->type("Threads");
    uint64_t head = r_->read_ptr(thr->field("_thread_list")->address);
    auto next_off = vm_->type("JavaThread")->field("_next")->offset;
    std::unordered_map<uint64_t, bool> seen;
    uint64_t t = head;
    while (t && !seen.count(t)) {
        seen[t] = true;
        out.push_back(read_thread(t));
        t = r_->read_ptr(t + next_off);
    }
}

void ThreadWalker::walk_smr(std::vector<ThreadSnapshot>& out) {
    auto smr = vm_->type("ThreadsSMRSupport");
    uint64_t tl = r_->read_ptr(smr->field("_java_thread_list")->address);
    if (!tl) return;
    auto tl_t = vm_->type("ThreadsList");
    uint32_t length = r_->read_u32(tl + tl_t->field("_length")->offset);
    uint64_t arr = r_->read_ptr(tl + tl_t->field("_threads")->offset);
    if (!arr || length == 0) return;
    auto raw = r_->read(arr, length * 8);
    for (uint32_t i = 0; i < length; ++i) {
        uint64_t t;
        std::memcpy(&t, raw.data() + i * 8, 8);
        if (t) out.push_back(read_thread(t));
    }
}

ThreadSnapshot ThreadWalker::read_thread(uint64_t jt) {
    ThreadSnapshot s{};
    s.address = jt;
    s.state_raw = r_->read_i32(jt + off_state_);
    auto it = state_names_.find(s.state_raw);
    s.state_name = (it != state_names_.end())
        ? it->second : "<unknown:" + std::to_string(s.state_raw) + ">";
    s.osthread_addr = off_osthread_present_ ? r_->read_ptr(jt + off_osthread_) : 0;
    s.os_tid = s.osthread_addr
        ? r_->read_u32(s.osthread_addr + off_osthread_tid_) : 0;
    s.thread_obj = r_->read_ptr(jt + off_threadobj_);
    s.vthread = off_vthread_ ? r_->read_ptr(jt + *off_vthread_) : 0;
    return s;
}


// ---------------------------------------------------------------------------
// ClassWalker — CLDG path only (sufficient for JDK 11+ default demos)
// ---------------------------------------------------------------------------

ClassWalker::ClassWalker(VMMeta* vm)
    : vm_(vm), r_(vm->reader())
{
    strategy_ = pick_strategy();
    auto kt = vm_->type("Klass");
    if (!kt) throw std::runtime_error("Klass type missing");
    off_name_ = kt->field("_name")->offset;
    off_layout_ = kt->field("_layout_helper")->offset;
    if (kt->has_field("_next_link")) {
        off_next_link_ = kt->field("_next_link")->offset;
        has_next_link_ = true;
    }
    if (strategy_ == "CLDG") {
        auto cld_t = vm_->type("ClassLoaderData");
        off_cld_klasses_ = cld_t->field("_klasses")->offset;
        off_cld_next_ = cld_t->field("_next")->offset;
    } else {
        // SystemDictionary path (JDK 8). Layout inherited from
        // BasicHashtable<mtInternal>. Template tags don't change layout.
        auto bh = vm_->type("BasicHashtable<mtInternal>");
        off_dict_size_ = bh->field("_table_size")->offset;
        off_dict_buckets_ = bh->field("_buckets")->offset;
        bucket_stride_ = vm_->type("HashtableBucket<mtInternal>")->size;
        entry_base_size_ = vm_->type("BasicHashtableEntry<mtInternal>")->size;
        off_entry_next_ = vm_->type("BasicHashtableEntry<mtInternal>")
            ->field("_next")->offset;
        // _literal (Klass*) is at the first slot past the base entry.
        off_entry_literal_ = entry_base_size_;
        off_entry_cld_ = vm_->type("DictionaryEntry")
            ->field("_loader_data")->offset;
    }
}

std::string ClassWalker::pick_strategy() const {
    auto cldg = vm_->type("ClassLoaderDataGraph");
    auto cld  = vm_->type("ClassLoaderData");
    auto kl   = vm_->type("Klass");
    if (cldg && cld && cld->has_field("_klasses")
            && kl && kl->has_field("_next_link"))
        return "CLDG";
    if (vm_->has_type("SystemDictionary")
            && vm_->has_type("BasicHashtable<mtInternal>")
            && vm_->has_type("DictionaryEntry"))
        return "SystemDictionary";
    throw std::runtime_error("no class-enumeration path");
}

std::vector<KlassSnapshot> ClassWalker::list() {
    std::vector<KlassSnapshot> out;
    if (strategy_ == "CLDG") walk_cldg(out);
    else                     walk_sysdict(out);
    return out;
}

void ClassWalker::walk_cldg(std::vector<KlassSnapshot>& out) {
    auto cldg = vm_->type("ClassLoaderDataGraph");
    uint64_t cld = r_->read_ptr(cldg->field("_head")->address);
    std::unordered_map<uint64_t, bool> cld_seen, k_seen;
    while (cld && !cld_seen.count(cld)) {
        cld_seen[cld] = true;
        uint64_t k = r_->read_ptr(cld + off_cld_klasses_);
        while (k && !k_seen.count(k)) {
            k_seen[k] = true;
            out.push_back(read_klass(k, cld));
            k = r_->read_ptr(k + off_next_link_);
        }
        cld = r_->read_ptr(cld + off_cld_next_);
    }
}

void ClassWalker::walk_sysdict(std::vector<KlassSnapshot>& out) {
    // JDK 8 path. Dictionary is a BasicHashtable<Klass*, mtClass>.
    // Pass 1: dictionary entries -> InstanceKlass*. Pass 2: walk each
    // InstanceKlass's _array_klasses chain (array klasses don't appear
    // in the dictionary). Pass 3: Universe primitive-type-array klasses.
    auto sd = vm_->type("SystemDictionary");
    if (!sd || !sd->has_field("_dictionary")) return;
    uint64_t dict_slot = sd->field("_dictionary")->address;
    uint64_t dict_ptr = r_->read_ptr(dict_slot);
    if (!dict_ptr) return;
    int32_t table_size = static_cast<int32_t>(
        r_->read_u32(dict_ptr + off_dict_size_));
    uint64_t buckets = r_->read_ptr(dict_ptr + off_dict_buckets_);
    if (!buckets || table_size <= 0) return;

    std::vector<uint64_t> instance_klasses;
    std::unordered_map<uint64_t, bool> seen_entries;
    for (int32_t i = 0; i < table_size; ++i) {
        uint64_t entry = r_->read_ptr(buckets + (uint64_t)i * bucket_stride_);
        while (entry && !seen_entries.count(entry)) {
            seen_entries[entry] = true;
            uint64_t klass = r_->read_ptr(entry + off_entry_literal_);
            uint64_t cld   = r_->read_ptr(entry + off_entry_cld_);
            if (klass) {
                instance_klasses.push_back(klass);
                out.push_back(read_klass(klass, cld));
            }
            entry = r_->read_ptr(entry + off_entry_next_);
        }
    }

    // Pass 2: array klass chains.
    auto ik = vm_->type("InstanceKlass");
    if (!ik || !ik->has_field("_array_klasses")) return;
    size_t array_off = ik->field("_array_klasses")->offset;
    size_t higher_off = 0; bool have_higher = false;
    for (const char* tn : {"ObjArrayKlass", "ArrayKlass"}) {
        if (vm_->has_type(tn) && vm_->type(tn)->has_field("_higher_dimension")) {
            higher_off = vm_->type(tn)->field("_higher_dimension")->offset;
            have_higher = true;
            break;
        }
    }
    if (!have_higher) return;
    std::unordered_map<uint64_t, bool> seen_arrays;
    for (uint64_t k : instance_klasses) {
        uint64_t ak = r_->read_ptr(k + array_off);
        while (ak && !seen_arrays.count(ak)) {
            seen_arrays[ak] = true;
            out.push_back(read_klass(ak, 0));
            ak = r_->read_ptr(ak + higher_off);
        }
    }

    // Pass 3: Universe primitive-type-array klasses (JDK 8 only).
    auto un = vm_->has_type("Universe") ? vm_->type("Universe") : nullptr;
    if (!un) return;
    static const char* prim_fields[] = {
        "_byteArrayKlassObj", "_charArrayKlassObj", "_shortArrayKlassObj",
        "_intArrayKlassObj", "_longArrayKlassObj", "_singleArrayKlassObj",
        "_doubleArrayKlassObj", "_boolArrayKlassObj",
    };
    for (const char* fn : prim_fields) {
        if (!un->has_field(fn)) continue;
        uint64_t ak = r_->read_ptr(un->field(fn)->address);
        while (ak && !seen_arrays.count(ak)) {
            seen_arrays[ak] = true;
            out.push_back(read_klass(ak, 0));
            ak = r_->read_ptr(ak + higher_off);
        }
    }
}

static std::string classify_layout_helper(int32_t lh) {
    if (lh > 0) return "instance";
    if (lh == 0) return "?";
    uint32_t u = static_cast<uint32_t>(lh);
    uint32_t tag = (u >> 30) & 0x3;
    if (tag == 3) return "type_array";
    if (tag == 2) return "obj_array";
    return "array";
}

KlassSnapshot ClassWalker::read_klass(uint64_t klass, uint64_t cld) {
    KlassSnapshot s{};
    s.address = klass;
    s.loader_data = cld;
    uint64_t nsym = r_->read_ptr(klass + off_name_);
    s.name = read_symbol(vm_, nsym);
    if (s.name.empty()) s.name = "<anon>";
    s.layout_helper = r_->read_i32(klass + off_layout_);
    s.kind = classify_layout_helper(s.layout_helper);
    return s;
}

} // namespace marrow
