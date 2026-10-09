#ifndef TITAN_FILTER_ENGINE_HPP
#define TITAN_FILTER_ENGINE_HPP

#include <cstdint>
#include <cstddef>
#include <atomic>
#include <new>
#include <array>
#include <chrono>
#include <system_error>
#include <limits>
#include <cstring>

namespace titan {

enum class FilterResult : uint8_t {
    Allow = 0,
    DropRateLimit,
    DropOutOfOrder,
    DropArenaOOM,
    DropOverflow
};

struct alignas(64) PacketDescriptor {
    const uint8_t* payload_ptr;
    uint32_t length;
    uint32_t flags;
    uint32_t flow_hash;
    uint32_t sequence_number;
    uint64_t hardware_timestamp;
    uint64_t arrival_time_ns;
    uint8_t reserved[16];
};

static_assert(sizeof(PacketDescriptor) == 64, "PacketDescriptor must be exactly 64 bytes (1 cache line)");

class ArenaAllocator {
public:
    explicit ArenaAllocator(size_t total_size)
        : total_size_(total_size), offset_(0), recycled_bytes_(0) {
        // Allocate raw memory block aligned to 64 bytes
        int res = posix_memalign(reinterpret_cast<void**>(&memory_), 64, total_size_);
        if (res != 0 || memory_ == nullptr) {
            throw std::bad_alloc();
        }
        std::memset(memory_, 0, total_size_);
    }

    ~ArenaAllocator() {
        if (memory_ != nullptr) {
            free(memory_);
            memory_ = nullptr;
        }
    }

    ArenaAllocator(const ArenaAllocator&) = delete;
    ArenaAllocator& operator=(const ArenaAllocator&) = delete;

    ArenaAllocator(ArenaAllocator&& other) noexcept
        : memory_(other.memory_),
          total_size_(other.total_size_),
          offset_(other.offset_.load(std::memory_order_relaxed)),
          recycled_bytes_(other.recycled_bytes_.load(std::memory_order_relaxed)) {
        other.memory_ = nullptr;
        other.total_size_ = 0;
        other.offset_.store(0, std::memory_order_relaxed);
        other.recycled_bytes_.store(0, std::memory_order_relaxed);
    }

    ArenaAllocator& operator=(ArenaAllocator&& other) noexcept {
        if (this != &other) {
            if (memory_ != nullptr) {
                free(memory_);
            }
            memory_ = other.memory_;
            total_size_ = other.total_size_;
            offset_.store(other.offset_.load(std::memory_order_relaxed), std::memory_order_relaxed);
            recycled_bytes_.store(other.recycled_bytes_.load(std::memory_order_relaxed), std::memory_order_relaxed);
            
            other.memory_ = nullptr;
            other.total_size_ = 0;
            other.offset_.store(0, std::memory_order_relaxed);
            other.recycled_bytes_.store(0, std::memory_order_relaxed);
        }
        return *this;
    }

    void* allocate(size_t size, size_t alignment = 8) {
        size_t current_offset = offset_.load(std::memory_order_relaxed);
        while (true) {
            uintptr_t current_address = reinterpret_cast<uintptr_t>(memory_) + current_offset;
            size_t adjustment = (alignment - (current_address % alignment)) % alignment;
            size_t needed = size + adjustment;

            if (current_offset + needed > total_size_) {
                return nullptr;
            }

            if (offset_.compare_exchange_weak(current_offset, current_offset + needed,
                                              std::memory_order_release,
                                              std::memory_order_relaxed)) {
                uintptr_t aligned_address = current_address + adjustment;
                return reinterpret_cast<void*>(aligned_address);
            }
        }
    }

    void reset() {
        offset_.store(0, std::memory_order_release);
        recycled_bytes_.store(0, std::memory_order_release);
    }

    void recycle_block(size_t size) {
        recycled_bytes_.fetch_add(size, std::memory_order_relaxed);
    }

    size_t available_bytes() const {
        size_t current_offset = offset_.load(std::memory_order_relaxed);
        if (current_offset >= total_size_) {
            return 0;
        }
        return total_size_ - current_offset;
    }

    size_t total_capacity() const {
        return total_size_;
    }

private:
    char* memory_ = nullptr;
    size_t total_size_;
    alignas(64) std::atomic<size_t> offset_;
    alignas(64) std::atomic<size_t> recycled_bytes_;
};

class SlidingWindowFlowTracker {
public:
    struct FlowState {
        uint32_t last_sequence;
        uint64_t last_seen_ns;
        uint32_t window_packets;
        uint32_t drop_count;
        uint8_t congestion_state;
        uint8_t padding[7];
    };

    explicit SlidingWindowFlowTracker(size_t table_size = 1024)
        : table_size_(table_size), mask_(table_size - 1) {
        if ((table_size & (table_size - 1)) != 0) {
            throw std::invalid_argument("Flow table size must be a power of two.");
        }
        table_ = new FlowState[table_size_];
        std::memset(table_, 0, sizeof(FlowState) * table_size_);
    }

    ~SlidingWindowFlowTracker() {
        delete[] table_;
    }

    SlidingWindowFlowTracker(const SlidingWindowFlowTracker&) = delete;
    SlidingWindowFlowTracker& operator=(const SlidingWindowFlowTracker&) = delete;

    FilterResult evaluate(uint32_t flow_hash, uint32_t sequence_number, uint64_t current_time_ns) {
        size_t index = flow_hash & mask_;
        FlowState& state = table_[index];

        // 1-second sliding window threshold in nanoseconds
        constexpr uint64_t kWindowIntervalNs = 1000000000ULL;
        constexpr uint32_t kMaxPacketsPerWindow = 50000;

        if (current_time_ns - state.last_seen_ns > kWindowIntervalNs) {
            state.last_seen_ns = current_time_ns;
            state.window_packets = 1;
            state.last_sequence = sequence_number;
            state.congestion_state = 0;
            return FilterResult::Allow;
        }

        state.window_packets++;
        if (state.window_packets > kMaxPacketsPerWindow) {
            state.drop_count++;
            state.congestion_state = 1;
            return FilterResult::DropRateLimit;
        }

        // Out-of-order check (allow small window for jitter)
        if (sequence_number < state.last_sequence && (state.last_sequence - sequence_number) > 1024) {
            state.drop_count++;
            return FilterResult::DropOutOfOrder;
        }

        if (sequence_number > state.last_sequence) {
            state.last_sequence = sequence_number;
        }

        return FilterResult::Allow;
    }

    void sweep_expired(uint64_t current_time_ns) {
        constexpr uint64_t kExpiryThresholdNs = 5000000000ULL; // 5 seconds
        for (size_t i = 0; i < table_size_; ++i) {
            if (table_[i].last_seen_ns != 0 && (current_time_ns - table_[i].last_seen_ns > kExpiryThresholdNs)) {
                std::memset(&table_[i], 0, sizeof(FlowState));
            }
        }
    }

private:
    size_t table_size_;
    size_t mask_;
    FlowState* table_;
};

template <typename T, size_t Capacity>
class SPSCQueue {
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be a power of two.");
public:
    SPSCQueue() : head_(0), tail_(0) {
        buffer_ = static_cast<T*>(operator new[](Capacity * sizeof(T)));
    }

    ~SPSCQueue() {
        T item;
        while (pop(item)) {
            // Drain remaining items
        }
        operator delete[](buffer_);
    }

    SPSCQueue(const SPSCQueue&) = delete;
    SPSCQueue& operator=(const SPSCQueue&) = delete;

    bool push(const T& item) {
        const size_t current_tail = tail_.load(std::memory_order_relaxed);
        const size_t current_head = head_.load(std::memory_order_acquire);

        if ((current_tail - current_head) >= Capacity) {
            return false; // Full
        }

        new (&buffer_[current_tail & kMask]) T(item);
        tail_.store(current_tail + 1, std::memory_order_release);
        return true;
    }

    bool push(T&& item) {
        const size_t current_tail = tail_.load(std::memory_order_relaxed);
        const size_t current_head = head_.load(std::memory_order_acquire);

        if ((current_tail - current_head) >= Capacity) {
            return false; // Full
        }

        new (&buffer_[current_tail & kMask]) T(std::move(item));
        tail_.store(current_tail + 1, std::memory_order_release);
        return true;
    }

    bool pop(T& item) {
        const size_t current_head = head_.load(std::memory_order_relaxed);
        const size_t current_tail = tail_.load(std::memory_order_acquire);

        if (current_head == current_tail) {
            return false; // Empty
        }

        item = std::move(buffer_[current_head & kMask]);
        buffer_[current_head & kMask].~T();
        head_.store(current_head + 1, std::memory_order_release);
        return true;
    }

    size_t size() const {
        size_t head_val = head_.load(std::memory_order_acquire);
        size_t tail_val = tail_.load(std::memory_order_acquire);
        if (tail_val >= head_val) {
            return tail_val - head_val;
        }
        return 0;
    }

    bool empty() const {
        return head_.load(std::memory_order_acquire) == tail_.load(std::memory_order_acquire);
    }

    size_t capacity() const {
        return Capacity;
    }

private:
    static constexpr size_t kMask = Capacity - 1;

    alignas(64) std::atomic<size_t> head_;
    alignas(64) std::atomic<size_t> tail_;
    T* buffer_;
};

class FilterEngine {
public:
    explicit FilterEngine(size_t arena_size, size_t flow_table_size)
        : arena_(arena_size), flow_tracker_(flow_table_size),
          total_ingress_(0), total_allowed_(0), total_dropped_(0),
          drop_overflow_(0), drop_oom_(0), drop_ratelimit_(0), drop_ooo_(0) {}

    ~FilterEngine() = default;

    FilterEngine(const FilterEngine&) = delete;
    FilterEngine& operator=(const FilterEngine&) = delete;

    bool ingest_packet(const uint8_t* raw_data, uint32_t length, uint32_t flow_hash, uint32_t seq, uint64_t hw_ts, uint64_t arrival_ns) {
        total_ingress_.fetch_add(1, std::memory_order_relaxed);

        void* mem = arena_.allocate(length, 64);
        if (mem == nullptr) {
            // OOM Protection / Arena Exhaustion Handling
            drop_oom_.fetch_add(1, std::memory_order_relaxed);
            total_dropped_.fetch_add(1, std::memory_order_relaxed);
            
            // Trigger recycling sweep
            flow_tracker_.sweep_expired(arrival_ns);
            arena_.reset();

            // Retry allocation once after sweep
            mem = arena_.allocate(length, 64);
            if (mem == nullptr) {
                return false;
            }
        }

        std::memcpy(mem, raw_data, length);

        PacketDescriptor desc;
        desc.payload_ptr = static_cast<const uint8_t*>(mem);
        desc.length = length;
        desc.flags = 0;
        desc.flow_hash = flow_hash;
        desc.sequence_number = seq;
        desc.hardware_timestamp = hw_ts;
        desc.arrival_time_ns = arrival_ns;
        std::memset(desc.reserved, 0, sizeof(desc.reserved));

        if (!ring_buffer_.push(desc)) {
            drop_overflow_.fetch_add(1, std::memory_order_relaxed);
            total_dropped_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }

        return true;
    }

    FilterResult process_next(PacketDescriptor& out_desc) {
        if (!ring_buffer_.pop(out_desc)) {
            return FilterResult::DropOverflow;
        }

        FilterResult res = flow_tracker_.evaluate(out_desc.flow_hash, out_desc.sequence_number, out_desc.arrival_time_ns);
        if (res == FilterResult::Allow) {
            total_allowed_.fetch_add(1, std::memory_order_relaxed);
        } else {
            total_dropped_.fetch_add(1, std::memory_order_relaxed);
            if (res == FilterResult::DropRateLimit) {
                drop_ratelimit_.fetch_add(1, std::memory_order_relaxed);
            } else if (res == FilterResult::DropOutOfOrder) {
                drop_ooo_.fetch_add(1, std::memory_order_relaxed);
            }
        }

        return res;
    }

    struct Metrics {
        uint64_t total_ingress;
        uint64_t total_allowed;
        uint64_t total_dropped;
        uint64_t drop_overflow;
        uint64_t drop_oom;
        uint64_t drop_ratelimit;
        uint64_t drop_ooo;
    };

    Metrics get_metrics() const {
        return Metrics{
            total_ingress_.load(std::memory_order_relaxed),
            total_allowed_.load(std::memory_order_relaxed),
            total_dropped_.load(std::memory_order_relaxed),
            drop_overflow_.load(std::memory_order_relaxed),
            drop_oom_.load(std::memory_order_relaxed),
            drop_ratelimit_.load(std::memory_order_relaxed),
            drop_ooo_.load(std::memory_order_relaxed)
        };
    }

    ArenaAllocator& get_arena() { return arena_; }
    SlidingWindowFlowTracker& get_flow_tracker() { return flow_tracker_; }

private:
    ArenaAllocator arena_;
    SlidingWindowFlowTracker flow_tracker_;
    SPSCQueue<PacketDescriptor, 65536> ring_buffer_;

    alignas(64) std::atomic<uint64_t> total_ingress_;
    alignas(64) std::atomic<uint64_t> total_allowed_;
    alignas(64) std::atomic<uint64_t> total_dropped_;
    alignas(64) std::atomic<uint64_t> drop_overflow_;
    alignas(64) std::atomic<uint64_t> drop_oom_;
    alignas(64) std::atomic<uint64_t> drop_ratel