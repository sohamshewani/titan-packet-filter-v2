#ifndef TITAN_TYPES_HPP
#define TITAN_TYPES_HPP

#include <cstdint>
#include <cstddef>
#include <atomic>
#include <new>
#include <cstring>
#include <array>
#include <chrono>

namespace titan {

// ============================================================================
// 1. DATA STRUCTURES: Packet Descriptor (64-byte Cache-Aligned)
// ============================================================================
struct alignas(64) PacketDescriptor {
    const uint8_t* payload;       // 8 bytes: Pointer to zero-copy payload in Arena/XDP ring
    uint32_t length;              // 4 bytes: Packet length in bytes
    uint32_t flags;               // 4 bytes: Status flags, truncation indicators, checksum status
    uint32_t flow_hash;           // 4 bytes: 4-tuple or RSS hash for flow tracking
    uint64_t hardware_timestamp;  // 8 bytes: NIC hardware capture timestamp (ns)
    uint8_t reserved[36];         // Pad out to exactly 64 bytes to fit single cache line

    constexpr PacketDescriptor() noexcept
        : payload(nullptr), length(0), flags(0), flow_hash(0), hardware_timestamp(0) {
        std::memset(reserved, 0, sizeof(reserved));
    }

    PacketDescriptor(const uint8_t* ptr, uint32_t len, uint32_t flg, uint32_t hash, uint64_t ts) noexcept
        : payload(ptr), length(len), flags(flg), flow_hash(hash), hardware_timestamp(ts) {
        std::memset(reserved, 0, sizeof(reserved));
    }
};

static_assert(sizeof(PacketDescriptor) == 64, "PacketDescriptor must be exactly 64 bytes");
static_assert(alignof(PacketDescriptor) == 64, "PacketDescriptor must be aligned to 64 bytes");

// ============================================================================
// 1. DATA STRUCTURES: Fixed-Size Arena Allocator
// ============================================================================
class ArenaAllocator {
private:
    uint8_t* buffer_;
    size_t capacity_;
    std::atomic<size_t> offset_;

public:
    explicit ArenaAllocator(size_t capacity) 
        : capacity_(capacity), offset_(0) {
        // Allocate 64-byte aligned contiguous memory block
        int ret = posix_memalign(reinterpret_cast<void**>(&buffer_), 64, capacity_);
        if (ret != 0 || buffer_ == nullptr) {
            throw std::bad_alloc();
        }
        std::memset(buffer_, 0, capacity_);
    }

    ~ArenaAllocator() noexcept {
        if (buffer_ != nullptr) {
            std::free(buffer_);
            buffer_ = nullptr;
        }
    }

    ArenaAllocator(const ArenaAllocator&) = delete;
    ArenaAllocator& operator=(const ArenaAllocator&) = delete;
    ArenaAllocator(ArenaAllocator&& other) noexcept 
        : buffer_(other.buffer_), capacity_(other.capacity_), offset_(other.load_offset()) {
        other.buffer_ = nullptr;
        other.capacity_ = 0;
        other.offset_store(0);
    }

    ArenaAllocator& operator=(ArenaAllocator&& other) noexcept {
        if (this != &other) {
            if (buffer_ != nullptr) {
                std::free(buffer_);
            }
            buffer_ = other.buffer_;
            capacity_ = other.capacity_;
            offset_store(other.load_offset());
            other.buffer_ = nullptr;
            other.capacity_ = 0;
            other.offset_store(0);
        }
        return *this;
    }

    [[nodiscard]] uint8_t* allocate(size_t size, size_t alignment = 64) noexcept {
        // Align allocation size up to match alignment requirements
        size_t current = offset_.load(std::memory_order_relaxed);
        while (true) {
            uint8_t* current_ptr = buffer_ + current;
            size_t space = capacity_ - current;
            void* ptr = static_cast<void*>(current_ptr);
            size_t space_left = space;
            
            if (std::align(alignment, size, ptr, space_left) == nullptr) {
                return nullptr; // Out of memory / Arena exhaustion
            }
            
            size_t aligned_offset = static_cast<size_t>(static_cast<uint8_t*>(ptr) - buffer_);
            size_t next_offset = aligned_offset + size;
            
            if (next_offset > capacity_) {
                return nullptr; // Arena exhaustion
            }
            
            if (offset_.compare_exchange_weak(current, next_offset, 
                                              std::memory_order_release, 
                                              std::memory_order_relaxed)) {
                return static_cast<uint8_t*>(ptr);
            }
        }
    }

    void reset() noexcept {
        offset_.store(0, std::memory_order_release);
    }

    [[nodiscard]] size_t capacity() const noexcept { return capacity_; }
    [[nodiscard]] size_t used() const noexcept { return offset_.load(std::memory_order_relaxed); }
    [[nodiscard]] size_t available() const noexcept { 
        size_t current = offset_.load(std::memory_order_relaxed);
        return current <= capacity_ ? capacity_ - current : 0; 
    }

private:
    [[nodiscard]] size_t load_offset() const noexcept {
        return offset_.load(std::memory_order_relaxed);
    }
    void offset_store(size_t val) noexcept {
        offset_.store(val, std::memory_order_relaxed);
    }
};

// ============================================================================
// 1. DATA STRUCTURES: Sliding-Window Flow Control State Machine
// ============================================================================
struct alignas(64) FlowState {
    std::atomic<uint64_t> last_sequence;
    std::atomic<uint64_t> window_mask;
    std::atomic<uint64_t> drop_count;
    std::atomic<uint64_t> last_active_timestamp;
    uint32_t flow_id;
    uint8_t state_flags;
    uint8_t padding[35];

    constexpr FlowState() noexcept
        : last_sequence(0), window_mask(0), drop_count(0), last_active_timestamp(0), flow_id(0), state_flags(0) {
        std::memset(padding, 0, sizeof(padding));
    }
};

static_assert(sizeof(FlowState) == 64, "FlowState must be 64 bytes for cache isolation");

class SlidingWindowTracker {
private:
    static constexpr size_t MAX_FLOWS = 4096;
    FlowState flows_[MAX_FLOWS];

public:
    SlidingWindowTracker() noexcept {
        for (size_t i = 0; i < MAX_FLOWS; ++i) {
            flows_[i].flow_id = static_cast<uint32_t>(i);
            flows_[i].last_sequence.store(0, std::memory_order_relaxed);
            flows_[i].window_mask.store(0, std::memory_order_relaxed);
            flows_[i].drop_count.store(0, std::memory_order_relaxed);
            flows_[i].last_active_timestamp.store(0, std::memory_order_relaxed);
            flows_[i].state_flags = 0;
        }
    }

    ~SlidingWindowTracker() noexcept = default;

    [[nodiscard]] bool validate_and_update(uint32_t flow_hash, uint64_t sequence, uint64_t current_timestamp) noexcept {
        size_t index = flow_hash & (MAX_FLOWS - 1);
        FlowState& flow = flows_[index];

        flow.last_active_timestamp.store(current_timestamp, std::memory_order_relaxed);

        uint64_t last_seq = flow.last_sequence.load(std::memory_order_acquire);

        if (sequence > last_seq) {
            uint64_t diff = sequence - last_seq;
            uint64_t mask = flow.window_mask.load(std::memory_order_relaxed);

            if (diff < 64) {
                mask <<= diff;
                mask |= 1ULL;
            } else {
                mask = 1ULL;
            }

            flow.window_mask.store(mask, std::memory_order_relaxed);
            flow.last_sequence.store(sequence, std::memory_order_release);
            return true; // Packet accepted
        } else {
            uint64_t diff = last_seq - sequence;
            if (diff < 64) {
                uint64_t mask = flow.window_mask.load(std::memory_order_relaxed);
                if ((mask & (1ULL << diff)) == 0) {
                    // Replayed or out of order but inside window, mark received
                    flow.window_mask.store(mask | (1ULL << diff), std::memory_order_relaxed);
                    return true;
                }
            }
            // Duplicate or volumetric flood attack vector detected
            flow.drop_count.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
    }

    void sweep_expired(uint64_t current_timestamp, uint64_t timeout_ns) noexcept {
        for (size_t i = 0; i < MAX_FLOWS; ++i) {
            uint64_t last_active = flows_[i].last_active_timestamp.load(std::memory_order_relaxed);
            if (last_active > 0 && (current_timestamp - last_active > timeout_ns)) {
                flows_[i].last_sequence.store(0, std::memory_order_release);
                flows_[i].window_mask.store(0, std::memory_order_relaxed);
                flows_[i].drop_count.store(0, std::memory_order_relaxed);
                flows_[i].last_active_timestamp.store(0, std::memory_order_relaxed);
                flows_[i].state_flags = 0;
            }
        }
    }
};

// ============================================================================
// 2. CONCURRENCY & 3. MEMORY LAYOUT: SPSC Circular Ring Buffer (Lock-Free)
// ============================================================================
template <typename T, size_t Capacity>
class SPSCQueue {
    static_assert((Capacity & (Capacity - 1)) == 0, "Ring Buffer Capacity must be a power of two");

private:
    // Cache-line isolation padding to prevent false sharing
    alignas(64) std::atomic<size_t> head_;
    alignas(64) std::atomic<size_t> tail_;
    alignas(64) std::array<T, Capacity> buffer_;

public:
    SPSCQueue() noexcept : head_(0), tail_(0) {}

    ~SPSCQueue() noexcept = default;

    SPSCQueue(const SPSCQueue&) = delete;
    SPSCQueue& operator=(const SPSCQueue&) = delete;
    SPSCQueue(SPSCQueue&&) = delete;
    SPSCQueue& operator=(SPSCQueue&&) = delete;

    [[nodiscard]] bool push(const T& item) noexcept {
        const size_t current_tail = tail_.load(std::memory_order_relaxed);
        const size_t current_head = head_.load(std::memory_order_acquire);

        if ((current_tail - current_head) >= Capacity) {
            return false; // Ring buffer full -> triggers overflow recovery
        }

        buffer_[current_tail & (Capacity - 1)] = item;
        tail_.store(current_tail + 1, std::memory_order_release);
        return true;
    }

    [[nodiscard]] bool push(T&& item) noexcept {
        const size_t current_tail = tail_.load(std::memory_order_relaxed);
        const size_t current_head = head_.load(std::memory_order_acquire);

        if ((current_tail - current_head) >= Capacity) {
            return false;
        }

        buffer_[current_tail & (Capacity - 1)] = std::move(item);
        tail_.store(current_tail + 1, std::memory_order_release);
        return true;
    }

    [[nodiscard]] bool pop(T& item) noexcept {
        const size_t current_head = head_.load(std::memory_order_relaxed);
        const size_t current_tail = tail_.load(std::memory_order_acquire);

        if (current_head == current_tail) {
            return false; // Ring buffer empty
        }

        item = std::move(buffer_[current_head & (Capacity - 1)]);
        head_.store(current_head + 1, std::memory_order_release);
        return true;
    }

    [[nodiscard]] size_t size() const noexcept {
        size_t current_tail = tail_.load(std::memory_order_acquire);
        size_t current_head = head_.load(std::memory_order_acquire);
        return current_tail >= current_head ? current_tail - current_head : 0;
    }

    [[nodiscard]] bool empty() const noexcept {
        return head_.load(std::memory_order_acquire) == tail_.load(std::memory_order_acquire);
    }

    [[nodiscard]] constexpr size_t capacity() const noexcept {
        return Capacity;
    }
};

} // namespace titan

#endif // TITAN_TYPES_HPP