#pragma once
// Thread + class walkers over VMMeta. Matches the strategy auto-selection
// logic from the Python walker.py — legacy Threads::_thread_list vs SMR
// ThreadsList, CLDG vs SystemDictionary.

#include "vm_meta.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace marrow {

struct ThreadSnapshot {
    uint64_t address;       // JavaThread*
    int32_t  state_raw;
    std::string state_name;
    uint32_t os_tid;
    uint64_t osthread_addr;
    uint64_t thread_obj;    // raw _threadObj (oop or OopHandle value)
    uint64_t vthread;       // raw _vthread on JDK 21+
};

class ThreadWalker {
public:
    explicit ThreadWalker(VMMeta* vm);

    std::vector<ThreadSnapshot> list();
    const std::string& strategy() const { return strategy_; }

private:
    std::string pick_strategy() const;
    void walk_legacy(std::vector<ThreadSnapshot>& out);
    void walk_smr(std::vector<ThreadSnapshot>& out);
    ThreadSnapshot read_thread(uint64_t jt_ptr);
    std::optional<uint64_t> resolve_inherited(const std::string& field,
                                              std::initializer_list<const char*> types);

    VMMeta* vm_;
    Reader* r_;
    std::string strategy_;
    size_t off_state_ = 0, off_osthread_ = 0, off_threadobj_ = 0;
    size_t off_osthread_tid_ = 0;
    std::optional<uint64_t> off_vthread_;
    bool off_osthread_present_ = true;

    std::unordered_map<int, std::string> state_names_;
};


struct KlassSnapshot {
    uint64_t address;
    std::string name;
    std::string kind;  // "instance" | "obj_array" | "type_array" | "array" | "?"
    int32_t layout_helper;
    uint64_t loader_data;
};

class ClassWalker {
public:
    explicit ClassWalker(VMMeta* vm);
    std::vector<KlassSnapshot> list();
    const std::string& strategy() const { return strategy_; }

private:
    std::string pick_strategy() const;
    void walk_cldg(std::vector<KlassSnapshot>& out);
    void walk_sysdict(std::vector<KlassSnapshot>& out);
    KlassSnapshot read_klass(uint64_t klass_ptr, uint64_t cld);

    VMMeta* vm_;
    Reader* r_;
    std::string strategy_;
    size_t off_name_ = 0, off_layout_ = 0;
    size_t off_next_link_ = 0;
    size_t off_cld_klasses_ = 0, off_cld_next_ = 0;
    bool has_next_link_ = false;
    // SystemDictionary strategy state (JDK 8 path).
    size_t off_dict_size_ = 0, off_dict_buckets_ = 0;
    size_t bucket_stride_ = 0, entry_base_size_ = 0;
    size_t off_entry_next_ = 0, off_entry_literal_ = 0;
    size_t off_entry_cld_ = 0;
};


// Decode a HotSpot Symbol into its UTF-8 string content. Works across
// every JDK 8..25 — each exports Symbol::_length (u2) and Symbol::_body.
std::string read_symbol(VMMeta* vm, uint64_t sym_addr);

} // namespace marrow
