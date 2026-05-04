#pragma once
// Clone an InstanceKlass into a target-owned VirtualAllocEx page, give it
// a fresh Symbol name, and splice it into the owning ClassLoaderData's
// _klasses linked list. ClassWalker will then enumerate the clone under
// its new name.
//
// Level-1 only: the clone is reachable by metadata-walk but NOT by narrow
// klass encoding, since our page lies outside the metaspace base range
// CompressedKlassPointers uses. Allocating instances OF the clone would
// require a metaspace-resident slot, which is not provided here.

#include "vm_meta.hpp"
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace marrow {

struct ClonedKlass {
    uint64_t clone_addr;    // our page holding the cloned Klass bytes
    uint64_t new_symbol;    // the Symbol backing the new name
    uint64_t donor_addr;    // original Klass we cloned from
    uint64_t cld_addr;      // ClassLoaderData we spliced into
    uint64_t old_head;      // previous cld._klasses (for revert)
};

// Allocate a Symbol with UTF-8 body `name` in the target. Marks its
// refcount as permanent so HotSpot never frees it.
uint64_t alloc_symbol(VMMeta* vm, const std::string& name);

// Clone `donor_klass` (InstanceKlass*) and register it as
// `ClassLoaderData._klasses` head under `new_name`.
ClonedKlass clone_klass(VMMeta* vm, uint64_t donor_klass,
                         const std::string& new_name);

// Remove the clone from the CLD list and free both pages. Safe to call on
// a ClonedKlass produced by clone_klass.
void unclone_klass(VMMeta* vm, const ClonedKlass& c);

// Level 2: like clone_klass but also allocates a fresh _methods array and
// duplicates every Method+ConstMethod into our pages. `bytecode_patch`
// mutates the cloned ConstMethod's body in-place before write — pass a
// null lambda to preserve the original bytecode.
struct DeepClonedKlass {
    ClonedKlass base;
    uint64_t new_methods_array;
    std::vector<uint64_t> new_methods;       // Method* in our pages
    std::vector<uint64_t> new_const_methods; // ConstMethod* in our pages
};

using BytecodePatch = std::function<void(const std::string& method_name,
                                          std::vector<uint8_t>& bytecode)>;

DeepClonedKlass clone_klass_deep(VMMeta* vm, uint64_t donor_klass,
                                  const std::string& new_name,
                                  BytecodePatch patch = nullptr);

void unclone_klass_deep(VMMeta* vm, const DeepClonedKlass& d);

// Level 3: clone_klass + register the clone in its CLD's SystemDictionary
// so a bucket walk over `_dictionary._buckets[hash % size]` finds it.
// Layout is discovered dynamically by dict_analyzer (no hardcoded offsets).
// JDK 11/17 only — JDK 21+ doesn't export Dictionary.
struct SysDictCloneResult {
    ClonedKlass base;
    uint64_t dictionary;
    uint64_t bucket_addr;
    uint64_t old_bucket_head;
    uint64_t new_entry;
    int32_t bucket_index;
    uint32_t hash;
};

SysDictCloneResult
clone_and_register_in_sysdict(VMMeta* vm, uint64_t donor_klass,
                              const std::string& new_name);

void unregister_from_sysdict(VMMeta* vm, const SysDictCloneResult& r);

// Replace the live Class.forName("<donor_name>") lookup result with a
// clone. We reuse the donor's Symbol* as the clone's name (so pointer
// equality holds in HotSpot's DictionaryEntry::equals), copy the donor's
// DictionaryEntry._hash (so bucket lookup lands in the same chain), and
// splice our entry ahead of the donor's — find_entry walks head-first
// and returns ours. JDK 11/17 only.
struct ReplaceClassResult {
    ClonedKlass base;        // symbol is not ours — it's donor's
    uint64_t dictionary;
    uint64_t bucket_addr;
    uint64_t old_bucket_head;
    uint64_t new_entry;
    int32_t  bucket_index;
    uint32_t hash_reused;
};

ReplaceClassResult replace_class_in_sysdict(VMMeta* vm, uint64_t donor_klass);

void unreplace_class(VMMeta* vm, const ReplaceClassResult& r);

} // namespace marrow
