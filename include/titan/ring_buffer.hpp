#ifndef TITAN_RING_BUFFER_HPP
#define TITAN_RING_BUFFER_HPP

#include <atomic>
#include <cstdint>
#include <cstddef>
#include <new>
#include <type_traits>
#include <utility>

namespace titan {

constexpr std::size_t kCacheLineSize = 64;

struct alignas(kCacheLineSize) PacketDescriptor {
    const uint8_t* payload_ptr;
    uint32_t length;
    uint32_t flags;
    uint64_t flow_hash;
    uint64_t hardware_timestamp;
    uint8_t reserved[24]; // Pad to exactly 64 bytes
};

static_assert(sizeof(PacketDescriptor) == kCacheLineSize, "PacketDescriptor must be exactly 64 bytes.");
static_assert(alignof(PacketDescriptor) == kCacheLineSize, "PacketDescriptor must be aligned to 64 bytes.");

template <typename T, std::size_t Capacity>
class SPSCValueRingBuffer {
    static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be a power of two.");
    static_assert(std::is_trivial_v<T>, "SPSCValueRingBuffer requires trivial types for zero-overhead lockfree storage.");

public:
    SPSCValueRingBuffer() 
        : head_(0), tail_(0) {}

    ~SPSCValueRingBuffer() = default;

    SPSCValueRingBuffer(const SPSCValueRingBuffer&) = delete;
    SPSCValueRingBuffer& operator=(const SPSCValueRingBuffer&) = delete;
    SPSCValueRingBuffer(SPSCValueRingBuffer&&) = delete;
    SPSCValueRingBuffer& operator=(SPSCValueRingBuffer&&) = delete;

    [[nodiscard]] bool push(const T& item) noexcept {
        const std::size_t current_tail = tail_.load(std::memory_order_relaxed);
        const std::size_t current_head = head_.load(std::memory_order_acquire);

        if ((current_tail - current_head) >= Capacity) {
            return false;
        }

        buffer_[current_tail & kMask] = item;
        tail_.store(current_tail + 1, std::memory_order_release);
        return true;
    }

    [[nodiscard]] bool push(T&& item) noexcept {
        const std::size_t current_tail = tail_.load(std::memory_order_relaxed);
        const std::size_t current_head = head_.load(std::memory_order_acquire);

        if ((current_tail - current_head) >= Capacity) {
            return false;
        }

        buffer_[current_tail & kMask] = std::move(item);
        tail_.store(current_tail + 1, std::memory_order_release);
        return true;
    }

    [[nodiscard]] bool pop(T& item) noexcept {
        const std::size_t current_head = head_.load(std::memory_order_relaxed);
        const std::size_t current_tail = tail_.load(std::memory_order_acquire);

        if (current_head == current_tail) {
            return false;
        }

        item = std::move(buffer_[current_head & kMask]);
        head_.store(current_head + 1, std::memory_order_release);
        return true;
    }

    [[nodiscard]] bool empty() const noexcept {
        return head_.load(std::memory_order_acquire) == tail_.load(std::memory_order_acquire);
    }

    [[nodiscard]] bool full() const noexcept {
        const std::size_t current_tail = tail_.load(std::memory_order_relaxed);
        const std::size_t current_head = head_.load(std::memory_order_acquire);
        return (current_tail - current_head) >= Capacity;
    }

    [[nodiscard]] std::size_t size() const noexcept {
        std::size_t current_head = head_.load(std::memory_order_acquire);
        std::size_t current_tail = tail_.load(std::memory_order_acquire);
        if (current_tail >= current_head) {
            return current_tail - current_head;
        }
        return 0;
    }

    [[nodiscard]] constexpr std::size_t capacity() const noexcept {
        return Capacity;
    }

private:
    static constexpr std::size_t kMask = Capacity - 1;

    alignas(kCacheLineSize) std::atomic<std::size_t> head_;
    alignas(kCacheLineSize) std::atomic<std::size_t> tail_;
    alignas(kCacheLineSize) T buffer_[Capacity];
};

} // namespace titan

#endif // TITAN_RING_BUFFER_HPP