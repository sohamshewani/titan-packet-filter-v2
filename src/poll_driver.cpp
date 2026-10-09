#include "poll_driver.hpp"

#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <iostream>
#include <chrono>

namespace titan {

PollDriver::PollDriver(int socket_fd, ArenaAllocator& arena, SPSCQueue& ring_buffer)
    : socket_fd_(socket_fd),
      epoll_fd_(-1),
      arena_(arena),
      ring_buffer_(ring_buffer),
      running_(false) {
    if (socket_fd_ < 0) {
        throw std::invalid_argument("PollDriver received an invalid socket file descriptor.");
    }
}

PollDriver::~PollDriver() {
    stop();
}

bool PollDriver::set_non_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        return false;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1;
}

void PollDriver::initialize_epoll() {
    if (!set_non_blocking(socket_fd_)) {
        throw std::runtime_error("Failed to set socket file descriptor to non-blocking mode.");
    }

    epoll_fd_ = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd_ == -1) {
        throw std::runtime_error("Failed to create epoll file descriptor: " + std::string(strerror(errno)));
    }

    struct epoll_event ev;
    std::memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLET | EPOLLRDHUP | EPOLLERR;
    ev.data.fd = socket_fd_;

    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, socket_fd_, &ev) == -1) {
        int saved_errno = errno;
        close(epoll_fd_);
        epoll_fd_ = -1;
        throw std::runtime_error("Failed to add socket to epoll instance: " + std::string(strerror(saved_errno)));
    }
}

void PollDriver::start() {
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        return; // Already running
    }

    initialize_epoll();

    poller_thread_ = std::thread(&PollDriver::poll_loop, this);
}

void PollDriver::stop() {
    bool expected = true;
    if (!running_.compare_exchange_strong(expected, false, std::memory_order_acq_rel)) {
        return; // Already stopped or stopping
    }

    if (epoll_fd_ != -1) {
        // Trigger a dummy write or shutdown to wake up epoll if blocked, 
        // or join thread which will exit on running_ == false via timeout/interrupt.
        shutdown(socket_fd_, SHUT_RDWR);
    }

    if (poller_thread_.joinable()) {
        poller_thread_.join();
    }

    if (epoll_fd_ != -1) {
        close(epoll_fd_);
        epoll_fd_ = -1;
    }
}

void PollDriver::poll_loop() {
    const int kMaxEvents = 64;
    struct epoll_event events[kMaxEvents];

    while (running_.load(std::memory_order_acquire)) {
        int nfds = epoll_wait(epoll_fd_, events, kMaxEvents, 100); // 100ms timeout for graceful shutdown check
        if (nfds < 0) {
            if (errno == EINTR) {
                continue;
            }
            // Log system error and break or recover
            break;
        }

        for (int i = 0; i < nfds; ++i) {
            if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN))) {
                // Handle socket error or hangup
                running_.store(false, std::memory_order_release);
                break;
            }

            // Edge-triggered mode: must drain the socket completely
            if (events[i].data.fd == socket_fd_) {
                drain_socket();
            }
        }
    }
}

void PollDriver::drain_socket() {
    while (true) {
        // Prepare temporary stack buffer for packet framing header or direct read
        // In a true zero-copy AF_XDP pipeline, we map umem frames. 
        // Here we simulate zero-copy arena ingestion using direct socket reads into arena space.
        
        // Allocate space for max standard MTU packet (e.g., 9000 bytes for jumbo frames)
        const size_t kMaxPacketSize = 9000;
        
        // Attempt allocation in arena before reading to guarantee zero-copy destination
        uint8_t* allocation = arena_.allocate(kMaxPacketSize, alignof(PacketDescriptor));
        if (!allocation) {
            // Arena exhaustion: trigger recycling sweep or drop packet
            arena_.reset(); // Fallback recycling sweep for survival
            allocation = arena_.allocate(kMaxPacketSize, alignof(PacketDescriptor));
            if (!allocation) {
                // Drop frame, increment metrics, and drain socket via discard read
                uint8_t discard_buf[kMaxPacketSize];
                ssize_t dropped_bytes = read(socket_fd_, discard_buf, kMaxPacketSize);
                if (dropped_bytes <= 0) {
                    break;
                }
                continue;
            }
        }

        ssize_t bytes_read = read(socket_fd_, allocation, kMaxPacketSize);
        if (bytes_read < 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                // Socket fully drained; release unused arena tail space if possible or keep simple
                break;
            } else {
                // Real read error
                break;
            }
        } else if (bytes_read == 0) {
            // EOF / Remote closed connection
            break;
        }

        // Construct Packet Descriptor
        PacketDescriptor desc;
        desc.payload = allocation;
        desc.length = static_cast<uint32_t>(bytes_read);
        desc.flags = 0;
        desc.flow_hash = calculate_flow_hash(allocation, bytes_read);
        
        auto now = std::chrono::high_resolution_clock::now();
        desc.hardware_timestamp = std::chrono::duration_cast<std::chrono::nanoseconds>(
            now.time_since_epoch()).count();

        // Push to SPSC Ring Buffer
        while (!ring_buffer_.push(desc)) {
            // Ring overflow recovery: handle gracefully by dropping or applying backpressure
            // Since this is SPSC, we drop oldest or current packet and increment drop counter.
            // For rigorous safety, we break out or drop this frame to prevent blocking I/O thread.
            break;
        }
    }
}

uint32_t PollDriver::calculate_flow_hash(const uint8_t* data, size_t length) const {
    // Fast non-cryptographic hash (Jenkins one-at-a-time or FNV-1a) for flow identification
    uint32_t hash = 2166136261u;
    // Hash first 64 bytes or full packet if smaller for flow tuple approximation
    size_t limit = length < 64 ? length : 64;
    for (size_t i = 0; i < limit; ++i) {
        hash ^= static_cast<uint32_t>(data[i]);
        hash *= 16777619u;
    }
    return hash;
}

} // namespace titan