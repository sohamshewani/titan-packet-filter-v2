#ifndef TITAN_FLOW_WINDOW_HPP
#define TITAN_FLOW_WINDOW_HPP

#include <cstdint>
#include <cstddef>
#include <atomic>
#include <chrono>
#include <new>
#include <limits>

namespace titan {

struct alignas(64) PacketDescriptor {
    const uint8_t* payload_ptr;
    uint32_t length;
    uint32_t flags;
    uint64_t flow_hash;
    uint64_t hw_timestamp;
    uint8_t padding[24];
};

static_assert(sizeof(PacketDescriptor) == 64, "PacketDescriptor must be exactly 64 bytes to fit a cache line.");

class FixedSizeArena {
public:
    explicit FixedSizeArena(size_t total_size)
        : size_(total_size), offset_(0), recycled_offset_(0) {
        storage_ = static_cast<uint8_t*>(::operator new(total_size, std::align_val_t{64}));
    }

    ~FixedSizeArena() {
        if (storage_) {
            ::operator delete(storage_, std::align_val_t{64});
        }
    }

    FixedSizeArena(const FixedSizeArena&) = delete;
    FixedSizeArena& operator=(const FixedSizeArena&) = delete;
    FixedSizeArena(FixedSizeArena&&) noexcept = delete;
    FixedSizeArena& operator=(FixedSizeArena&&) noexcept = delete;

    uint8_t* allocate(size_t bytes) {
        size_t aligned_bytes = (bytes + 7) & ~static_cast<size_t>(7);
        size_t current_offset = offset_.load(std::memory_order_relaxed);
        
        while (true) {
            if (current_offset + aligned_bytes > size_) {
                return nullptr;
            }
            if (offset_.compare_exchange_weak(current_offset, current_offset + aligned_bytes,
                                              std::memory_order_relaxed,
                                              std::memory_order_relaxed)) {
                return storage_ + current_offset;
            }
        }
    }

    void reset() {
        offset_.store(0, std::memory_order_relaxed);
        recycled_offset_.store(0, std::memory_order_relaxed);
    }

    size_t capacity() const {
        return size_;
    }

    size_t used_bytes() const {
        return offset_.load(std::memory_order_relaxed);
    }

private:
    size_t size_;
    std::atomic<size_t> offset_;
    std::atomic<size_t> recycled_offset_;
    uint8_t* storage_;
};

struct FlowState {
    std::atomic<uint64_t> expected_sequence;
    std::atomic<uint64_t> last_seen_timestamp;
    std::atomic<uint32_t> window_drops;
    std::atomic<uint32_t> state_flags;
};

class SlidingWindowFlowTracker {
public:
    explicit SlidingWindowFlowTracker(uint64_t timeout_ns = 5000000000ULL)
        : timeout_threshold_ns_(timeout_ns) {
        for (size_t i = 0; i < TABLE_SIZE; ++i) {
            table_[i].expected_sequence.store(0, std::memory_order_relaxed);
            table_[i].last_seen_timestamp.store(0, std::memory_order_relaxed);
            table_[i].window_drops.store(0, std::memory_order_relaxed);
            table_[i].state_flags.store(0, std::memory_order_relaxed);
        }
    }

    ~SlidingWindowFlowTracker() = default;

    SlidingWindowFlowTracker(const SlidingWindowFlowTracker&) = delete;
    SlidingWindowFlowTracker& operator=(const SlidingWindowFlowTracker&) = delete;
    SlidingWindowFlowTracker(SlidingWindowFlowTracker&&) noexcept = delete;
    SlidingWindowFlowTracker& operator=(SlidingWindowFlowTracker&&) noexcept = delete;

    bool validate_and_update(uint64_t flow_hash, uint64_t sequence_number, uint64_t current_timestamp) {
        size_t index = hash_to_index(flow_hash);
        FlowState& flow = table_[index];

        uint64_t last_ts = flow.last_seen_timestamp.load(std::memory_order_relaxed);
        if (current_timestamp > last_ts && (current_timestamp - last_ts > timeout_threshold_ns_)) {
            flow.expected_sequence.store(sequence_number, std::memory_order_relaxed);
            flow.last_seen_timestamp.store(current_timestamp, std::memory_order_relaxed);
            flow.state_flags.store(0, std::memory_order_relaxed);
            return true;
        }

        uint64_t expected = flow.expected_sequence.load(std::memory_order_relaxed);

        if (sequence_number < expected) {
            flow.window_drops.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        if (sequence_number >= expected + WINDOW_SIZE) {
            flow.window_drops.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        uint64_t new_expected = sequence_number + 1;
        while (!flow.expected_sequence.compare_exchange_weak(expected, new_expected,
                                                             std::memory_order_release,
                                                             std::memory_order_relaxed)) {
            if (sequence_number < expected) {
                flow.window_drops.fetch_add(1, std::memory_order_relaxed);
                return false;
            }
            if (sequence_number >= expected + WINDOW_SIZE) {
                flow.window_drops.fetch_add(1, std::memory_order_relaxed);
                return false;
            }
            new_expected = sequence_number + 1;
        }

        flow.last_seen_timestamp.store(current_timestamp, std::memory_order_relaxed);
        return true;
    }

    void sweep_expired(uint64_t current_timestamp) {
        for (size_t i = 0; i < TABLE_SIZE; ++i) {
            uint64_t last_ts = table_[i].last_seen_timestamp.load(std::memory_order_relaxed);
            if (last_ts != 0 && (current_timestamp > last_ts) && 
                (current_timestamp - last_ts > timeout_threshold_ns_)) {
                table_[i].expected_sequence.store(0, std::memory_order_relaxed);
                table_[i].last_seen_timestamp.store(0, std::memory_order_relaxed);
                table_[i].window_drops.store(0, std::memory_order_relaxed);
                table_[i].state_flags.store(0, std::memory_order_relaxed);
            }
        }
    }

private:
    static constexpr size_t TABLE_SIZE = 65536;
    static constexpr size_t WINDOW_SIZE = 1024;
    FlowState table_[TABLE_SIZE];
    uint64_t timeout_threshold_ns_;

    inline size_t hash_to_index(uint64_t flow_hash) const {
        return static_cast<size_t>(flow_hash & (TABLE_SIZE - 1));
    }
};

template <typename T, size_t Capacity>
class SPSCRingBuffer {
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be a power of two.");
public:
    SPSCRingBuffer() : head_(0), tail_(0) {
        buffer_ = static_cast<T*>(::operator new(Capacity * sizeof(T), std::align_val_t{64}));
    }

    ~SPSCRingBuffer() {
        while (!empty()) {
            T item;
            pop(item);
        }
        ::operator delete(buffer_, std::align_val_t{64});
    }

    SPSCRingBuffer(const SPSCRingBuffer&) = delete;
    SPSCRingBuffer& operator=(const SPSCRingBuffer&) = delete;
    SPSCRingBuffer(SPSCRingBuffer&&) noexcept = delete;
    SPSCRingBuffer& operator=(SPSCRingBuffer&&) noexcept = delete;

    bool push(const T& item) {
        const size_t current_tail = tail_.load(std::memory_order_relaxed);
        const size_t current_head = head_.load(std::memory_order_acquire);

        if ((current_tail - current_head) >= Capacity) {
            return false;
        }

        ::new (static_cast<void*>(&buffer_[current_tail & Mask])) T(item);
        tail_.store(current_tail + 1, std::memory_order_release);
        return true;
    }

    bool push(T&& item) {
        const size_t current_tail = tail_.load(std::memory_order_relaxed);
        const size_t current_head = head_.load(std::memory_order_acquire);

        if ((current_tail - current_head) >= Capacity) {
            return false;
        }

        ::new (static_cast<void*>(&buffer_[current_tail & Mask])) T(std::move(item));
        tail_.store(current_tail + 1, std::memory_order_release);
        return true;
    }

    bool pop(T& item) {
        const size_t current_head = head_.load(std::memory_order_relaxed);
        const size_t current_tail = tail_.load(std::memory_order_acquire);

        if (current_head == current_tail) {
            return false;
        }

        item = std::move(buffer_[current_head & Mask]);
        buffer_[current_head & Mask].~T();
        head_.store(current_head + 1, std::memory_order_release);
        return true;
    }

    bool empty() const {
        return head_.load(std::memory_order_relaxed) == tail_.load(std::memory_order_relaxed);
    }

    size_t size() const {
        size_t head = head_.load(std::memory_order_relaxed);
        size_t tail = tail_.load(std::memory_order_relaxed);
        if (tail >= head) {
            return tail - head;
        }
        return 0;
    }

    constexpr size_t capacity() const {
        return Capacity;
    }

private:
    static constexpr size_t Mask = Capacity - 1;

    alignas(64) std::atomic<size_t> head_;
    alignas(64) std::atomic<size_t> tail_;
    T* buffer_;
};

} // namespace titan

#endif // TITAN_FLOW_WINDOW_HPP