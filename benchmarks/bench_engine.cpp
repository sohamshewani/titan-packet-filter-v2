#include <iostream>
#include <vector>
#include <chrono>
#include <numeric>
#include <algorithm>
#include <cstdint>
#include <iomanip>

// Mocking the 'titan-packet-filter' core interfaces for the microbenchmark.
// In a real-world scenario, this would include the actual library headers.
namespace titan {
    enum class Verdict {
        ALLOW,
        DROP,
        MODIFY
    };

    struct Packet {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
        uint8_t  protocol;
        const uint8_t* payload;
        size_t payload_len;
    };

    class PacketFilter {
    public:
        PacketFilter() = default;
        ~PacketFilter() = default;

        // Simulate rule compilation/setup
        bool initialize() {
            return true;
        }

        // The core operation we are benchmarking
        inline Verdict evaluate(const Packet& pkt) const {
            // Simulated micro-rule evaluation workload
            if (pkt.protocol == 6 && pkt.dst_port == 80) {
                return Verdict::ALLOW;
            }
            if (pkt.src_ip == 0xC0A80101) { // 192.168.1.1
                return Verdict::DROP;
            }
            return Verdict::ALLOW;
        }
    };
}

int main() {
    // Benchmark configuration
    const size_t WARMUP_ITERATIONS = 100000;
    const size_t BENCHMARK_ITERATIONS = 5000000;

    titan::PacketFilter filter;
    if (!filter.initialize()) {
        std::cerr << "Failed to initialize titan-packet-filter" << std::endl;
        return 1;
    }

    // Prepare a standard test packet
    uint8_t dummy_payload[64] = {0};
    titan::Packet pkt{
        .src_ip = 0xC0A80105,   // 192.168.1.5
        .dst_ip = 0x0A000001,   // 10.0.0.1
        .src_port = 12345,
        .dst_port = 80,
        .protocol = 6,          // TCP
        .payload = dummy_payload,
        .payload_len = sizeof(dummy_payload)
    };

    // Warmup phase
    for (size_t i = 0; i < WARMUP_ITERATIONS; ++i) {
        volatile auto verdict = filter.evaluate(pkt);
        (void)verdict;
    }

    // Latency collection buffer
    std::vector<uint64_t> latencies_ns;
    latencies_ns.reserve(BENCHMARK_ITERATIONS);

    // High-precision timing benchmark loop
    auto start_total = std::chrono::high_resolution_clock::now();

    for (size_t i = 0; i < BENCHMARK_ITERATIONS; ++i) {
        auto start_op = std::chrono::high_resolution_clock::now();
        
        volatile auto verdict = filter.evaluate(pkt);
        (void)verdict;

        auto end_op = std::chrono::high_resolution_clock::now();
        auto duration_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end_op - start_op).count();
        
        latencies_ns.push_back(static_cast<uint64_t>(duration_ns));
    }

    auto end_total = std::chrono::high_resolution_clock::now();
    auto total_duration_sec = std::chrono::duration<double>(end_total - start_total).count();

    // Compute metrics
    double ops_per_sec = static_cast<double>(BENCHMARK_ITERATIONS) / total_duration_sec;

    std::sort(latencies_ns.begin(), latencies_ns.end());

    uint64_t p50 = latencies_ns[BENCHMARK_ITERATIONS * 50 / 100];
    uint64_t p90 = latencies_ns[BENCHMARK_ITERATIONS * 90 / 100];
    uint64_t p99 = latencies_ns[BENCHMARK_ITERATIONS * 99 / 100];
    uint64_t p999 = latencies_ns[static_cast<size_t>(BENCHMARK_ITERATIONS * 99.9 / 100)];

    // Output formatted tabular metrics to stdout
    std::cout << "\n";
    std::cout << "=================================================================\n";
    std::cout << "          titan-packet-filter Microbenchmark Results             \n";
    std::cout << "=================================================================\n";
    std::cout << std::left << std::setw(30) << "Metric" << std::right << std::setw(30) << "Value" << "\n";
    std::cout << "-----------------------------------------------------------------\n";
    std::cout << std::left << std::setw(30) << "Total Iterations" << std::right << std::setw(30) << BENCHMARK_ITERATIONS << "\n";
    std::cout << std::left << std::setw(30) << "Total Time (s)" << std::right << std::setw(30) << std::fixed << std::setprecision(4) << total_duration_sec << "\n";
    std::cout << std::left << std::setw(30) << "Throughput (ops/sec)" << std::right << std::setw(30) << static_cast<uint64_t>(ops_per_sec) << "\n";
    std::cout << "-----------------------------------------------------------------\n";
    std::cout << std::left << std::setw(30) << "Latency p50 (ns)" << std::right << std::setw(30) << p50 << "\n";
    std::cout << std::left << std::setw(30) << "Latency p90 (ns)" << std::right << std::setw(30) << p90 << "\n";
    std::cout << std::left << std::setw(30) << "Latency p99 (ns)" << std::right << std::setw(30) << p99 << "\n";
    std::cout << std::left << std::setw(30) << "Latency p99.9 (ns)" << std::right << std::setw(30) << p999 << "\n";
    std::cout << "=================================================================\n";
    std::cout << std::endl;

    return 0;
}