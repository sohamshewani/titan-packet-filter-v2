#ifndef TITAN_ARENA_HPP
#define TITAN_ARENA_HPP

#include <cstddef>
#include <cstdint>
#include <new>
#include <atomic>
#include <system_error>

namespace titan {

class Arena {
public:
    explicit Arena(std::size_t total_size)
        : size_(total_size), offset_(0), recycled_bytes_(0) {
        if (total_size == 0) {
            throw std::system_error(
                std::make_error_code(std::errc::invalid_argument),
                "Arena size must be greater than zero."
            );
        }
        
        // Allocate raw memory block aligned to cache lines (64 bytes)
        buffer_ = static_cast<std::byte*>(::operator new(total_size, std::align_val_t{64}));
        if (!buffer_) {
            throw std::system_error(
                std::make_error_code(std::errc::not_enough_memory),
                "Failed to allocate memory for Titan Arena."
            );
        }
    }

    ~Arena() noexcept {
        if (buffer_ != nullptr) {
            ::operator delete(buffer_, std::align_val_t{64});
            buffer_ = nullptr;
        }
    }

    // Delete copy and move semantics to ensure strict memory ownership and thread isolation
    Arena(const Arena&) = delete;
    Arena& operator=(const Arena&) = delete;
    Arena(Arena&&) noexcept = delete;
    Arena& operator=(Arena&&) noexcept = delete;

    [[nodiscard]] void* allocate(std::size_t bytes, std::size_t alignment = alignof(std::max_align_t)) {
        if (bytes == 0) {
            return nullptr;
        }

        std::size_t current_offset = offset_.load(std::memory_order_relaxed);
        
        while (true) {
            // Calculate current pointer address
            std::uintptr_t current_address = reinterpret_cast<std::uintptr_t>(buffer_ + current_offset);
            
            // Compute alignment padding
            std::size_t padding = 0;
            std::uintptr_t modulo = current_address % alignment;
            if (modulo != 0) {
                padding = alignment - modulo;
            }

            std::size_t required_space = bytes + padding;
            std::size_t next_offset = current_offset + required_space;

            if (next_offset > size_) {
                // Arena exhaustion detected. Return nullptr to signal OOM / recycling requirement.
                return nullptr;
            }

            // Attempt atomic pointer bumping (CAS)
            if (offset_.compare_exchange_weak(
                    current_offset,
                    next_offset,
                    std::memory_order_acq_rel,
                    std::memory_order_relaxed)) {
                
                std::byte* allocated_ptr = buffer_ + current_offset + padding;
                return static_cast<void*>(allocated_ptr);
            }
            // Loop retries automatically if another thread bumped offset concurrently
        }
    }

    void reset() noexcept {
        offset_.store(0, std::memory_order_release);
        recycled_bytes_.store(0, std::memory_order_release);
    }

    [[nodiscard]] std::size_t capacity() const noexcept {
        return size_;
    }

    [[nodiscard]] std::size_t bytes_allocated() const noexcept {
        return offset_.load(std::memory_order_relaxed);
    }

    [[nodiscard]] std::size_t available_bytes() const noexcept {
        std::size_t current = offset_.load(std::memory_order_relaxed);
        return (current >= size_) ? 0 : (size_ - current);
    }

    // Triggered by the failure recovery subsystem during sliding-window sweeps
    void sweep_recycle(std::size_t freed_bytes) noexcept {
        recycled_bytes_.fetch_add(freed_bytes, std::memory_order_relaxed);
        // Monotonically incremented arena can accept a logical adjustment or full reset
        // depending on the sliding-window epoch expiration model.
        std::size_t current_offset = offset_.load(std::memory_order_relaxed);
        if (freed_bytes <= current_offset) {
            offset_.fetch_sub(freed_bytes, std::memory_order_acq_rel);
        } else {
            offset_.store(0, std::memory_order_release);
        }
    }

private:
    std::size_t size_;
    std::byte* buffer_{nullptr};
    alignas(64) std::atomic<std::size_t> offset_{0};
    alignas(64) std::atomic<std::size_t> recycled_bytes_{0};
};

} // namespace titan

#endif // TITAN_ARENA_HPP