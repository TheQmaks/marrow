#include "tlab.hpp"
#include "walker.hpp"
#include <windows.h>
#include <cstring>
#include <optional>
#include <stdexcept>

namespace marrow {

static size_t align_up(size_t x, size_t a) { return (x + a - 1) & ~(a - 1); }

TLABAllocator::TLABAllocator(VMMeta* vm, OopDecoder* decoder, ZGCDecoder* zgc)
    : vm_(vm), r_(vm->reader()), dec_(decoder), zgc_(zgc)
{
    const TypeInfo* thread_t = vm->type("Thread");
    const TypeInfo* tlab_t   = vm->type("ThreadLocalAllocBuffer");
    const TypeInfo* klass_t  = vm->type("Klass");
    if (!thread_t || !tlab_t || !klass_t)
        throw std::runtime_error("Thread/TLAB/Klass type missing");
    off_thread_tlab_   = thread_t->field("_tlab")->offset;
    off_tlab_top_      = tlab_t->field("_top")->offset;
    off_tlab_end_      = tlab_t->field("_end")->offset;
    off_klass_layout_  = klass_t->field("_layout_helper")->offset;
}

std::vector<uint32_t> TLABAllocator::collect_tids()
{
    // NEVER include the calling thread. If the agent IPC thread is itself
    // attached as a JavaThread (which happens once try_xref_bootstrap runs),
    // suspending ourselves later in alloc_raw deadlocks.
    uint32_t self_tid = GetCurrentThreadId();
    std::vector<uint32_t> out;
    ThreadWalker tw(vm_);
    for (auto& t : tw.list())
        if (t.os_tid && t.os_tid != self_tid) out.push_back(t.os_tid);
    return out;
}

std::vector<void*> TLABAllocator::suspend_all(const std::vector<uint32_t>& tids)
{
    std::vector<void*> handles;
    for (uint32_t tid : tids) {
        HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
        if (h) { SuspendThread(h); handles.push_back(h); }
    }
    return handles;
}

void TLABAllocator::resume_all(const std::vector<void*>& handles)
{
    for (void* h : handles) { ResumeThread(HANDLE(h)); CloseHandle(HANDLE(h)); }
}

std::tuple<uint64_t, uint64_t, uint64_t>
TLABAllocator::pick_tlab(size_t bytes_needed)
{
    // Exclude the calling thread: we cannot SuspendThread(self) without
    // deadlocking, and the agent IPC thread is itself a JavaThread once
    // try_xref_bootstrap has attached it.
    uint32_t self_tid = GetCurrentThreadId();
    ThreadWalker tw(vm_);
    for (auto& t : tw.list()) {
        if (t.os_tid == self_tid) continue;
        uint64_t tlab = t.address + off_thread_tlab_;
        uint64_t top, end;
        try {
            top = r_->read_u64(tlab + off_tlab_top_);
            end = r_->read_u64(tlab + off_tlab_end_);
        } catch (...) { continue; }
        if (!top || !end) continue;
        if (end - top >= bytes_needed)
            return {t.address, top, end};
    }
    throw AllocationError("no JavaThread TLAB has enough free bytes");
}

void TLABAllocator::commit_tlab_top(uint64_t thread_ptr, uint64_t new_top)
{
    uint64_t addr = thread_ptr + off_thread_tlab_ + off_tlab_top_;
    r_->write(addr, &new_top, 8);
}

uint64_t TLABAllocator::borrow_mark_word(uint64_t klass_ptr)
{
    auto* mf = vm_->type("Klass")->field("_java_mirror");
    uint64_t raw = r_->read_u64(klass_ptr + mf->offset);
    uint64_t mirror = mf->type_string == "OopHandle" ? r_->read_u64(raw) : raw;
    // Under ZGC the oopStorage slot holds a coloured pointer; uncolour
    // before reading the mark word.
    if (zgc_ && zgc_->is_active()) mirror = zgc_->decode(mirror);
    if (mirror) {
        uint64_t mark = r_->read_u64(mirror);
        return mark & 0x7ull; // clear hash bits, keep low lock state
    }
    return 0x1ull; // unlocked prototype fallback
}

std::pair<uint64_t, uint64_t> TLABAllocator::alloc_raw(size_t size_bytes)
{
    if ((size_bytes & 7) || !size_bytes)
        throw AllocationError("alloc size must be nonzero and 8-aligned");

    // Pick a candidate TLAB UNSUSPENDED first — most JavaThreads in a
    // real workload sit blocked on I/O or wait, so their _top doesn't
    // move and we can hijack a slot without touching anyone else. Only
    // when our chosen donor advances its _top between the read and the
    // commit do we retry under suspend (as a fall-back).
    //
    // Eliminates the all-thread freeze that the alloc previously paid
    // on every call (visible to the application as a multi-millisecond
    // pause) — agent-side String allocation now fits inside hot hooks.
    auto try_alloc_unsuspended = [&]() -> std::optional<std::pair<uint64_t,uint64_t>> {
        auto picked = pick_tlab(size_bytes);
        uint64_t thread_ptr = std::get<0>(picked);
        uint64_t top        = std::get<1>(picked);
        uint64_t end        = std::get<2>(picked);
        (void)end;

        // Suspend ONLY the donor thread for the millisecond-window where
        // we bump _top and zero-fill. Other JavaThreads + GC workers stay
        // running; the JVM never observes a global pause.
        ThreadWalker tw(vm_);
        uint32_t donor_tid = 0;
        for (auto& t : tw.list()) {
            if (t.address == thread_ptr) { donor_tid = t.os_tid; break; }
        }
        if (!donor_tid) return std::nullopt;

        HANDLE donor = OpenThread(THREAD_SUSPEND_RESUME, FALSE, donor_tid);
        if (!donor) return std::nullopt;
        if (SuspendThread(donor) == DWORD(-1)) {
            CloseHandle(donor);
            return std::nullopt;
        }

        try {
            // Re-read _top after suspending the donor. If it moved since
            // pick_tlab read it, the donor allocated something else from
            // under us — bail and let caller retry.
            uint64_t cur_top = r_->read_u64(thread_ptr + off_thread_tlab_ + off_tlab_top_);
            if (cur_top != top) {
                ResumeThread(donor); CloseHandle(donor);
                return std::nullopt;
            }
            commit_tlab_top(thread_ptr, top + size_bytes);
            std::vector<uint8_t> zeros(size_bytes, 0);
            r_->write(top, zeros.data(), zeros.size());
        } catch (...) {
            ResumeThread(donor); CloseHandle(donor);
            throw;
        }
        ResumeThread(donor);
        CloseHandle(donor);
        return std::pair<uint64_t,uint64_t>{top, thread_ptr};
    };

    // First attempt: per-donor suspend only. Most calls land here.
    try {
        auto r = try_alloc_unsuspended();
        if (r) return *r;
    } catch (...) {
        // fall through
    }

    // Fall-back: suspend everyone and retry. This is the legacy path —
    // safe but expensive. Reached only on TLAB races / multi-threaded
    // contention.
    auto tids = collect_tids();
    auto handles = suspend_all(tids);
    try {
        auto picked = pick_tlab(size_bytes);
        uint64_t thread_ptr = std::get<0>(picked);
        uint64_t top        = std::get<1>(picked);
        commit_tlab_top(thread_ptr, top + size_bytes);
        std::vector<uint8_t> zeros(size_bytes, 0);
        r_->write(top, zeros.data(), zeros.size());
        resume_all(handles);
        return {top, thread_ptr};
    } catch (...) {
        resume_all(handles);
        throw;
    }
}

uint32_t TLABAllocator::encode_narrow_klass(uint64_t klass_ptr)
{
    const auto& kp = dec_->klass_params;
    if (!kp.enabled()) {
        if (klass_ptr > 0xFFFFFFFFull)
            throw AllocationError("klass > 32-bit with zero klass_params");
        return uint32_t(klass_ptr);
    }
    return uint32_t((klass_ptr - kp.base) >> kp.shift);
}

void TLABAllocator::write_header(uint64_t oop, uint64_t klass_ptr)
{
    uint64_t mark = borrow_mark_word(klass_ptr);
    r_->write(oop, &mark, 8);
    if (dec_->compressed_klass()) {
        uint32_t narrow = encode_narrow_klass(klass_ptr);
        r_->write(oop + 8, &narrow, 4);
    } else {
        r_->write(oop + 8, &klass_ptr, 8);
    }
}

uint64_t TLABAllocator::allocate_instance(uint64_t klass_ptr)
{
    int32_t lh = r_->read_i32(klass_ptr + off_klass_layout_);
    if (lh <= 0)
        throw AllocationError("klass has non-instance layout_helper");
    size_t size = align_up(size_t(lh) & ~size_t(0x7), 8);
    auto [oop, _] = alloc_raw(size);
    write_header(oop, klass_ptr);
    return oop;
}

uint64_t TLABAllocator::allocate_type_array(uint64_t klass_ptr, int32_t length)
{
    if (length < 0) throw AllocationError("negative array length");
    uint32_t lh_u = uint32_t(r_->read_i32(klass_ptr + off_klass_layout_));
    size_t header_size  = (lh_u >> 16) & 0xFF;
    size_t log2_element = lh_u & 0xFF;
    if (header_size != 12 && header_size != 16 && header_size != 20 && header_size != 24)
        throw AllocationError("implausible array header size from layout_helper");
    size_t elem_size = size_t(1) << log2_element;
    size_t total = align_up(header_size + size_t(length) * elem_size, 8);
    auto [oop, _] = alloc_raw(total);
    write_header(oop, klass_ptr);
    int32_t len = length;
    r_->write(oop + (header_size - 4), &len, 4);
    return oop;
}

size_t TLABAllocator::array_data_offset() const {
    return dec_->compressed_klass() ? 16 : 24;
}
size_t TLABAllocator::array_length_offset() const {
    return dec_->compressed_klass() ? 12 : 16;
}

} // namespace marrow
