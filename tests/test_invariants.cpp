#include <iostream>
#include <cstdint>
#include <vector>
#include <unordered_set>
#include <string>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <chrono>
#include <cassert>
#include <cstring>
#include <algorithm>

namespace Titan {

struct Packet {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    uint16_t payload_len;
    const uint8_t* payload;
};

enum class Action {
    ALLOW,
    DROP,
    REJECT
};

struct Rule {
    uint32_t src_ip;
    uint32_t src_mask;
    uint32_t dst_ip;
    uint32_t dst_mask;
    uint16_t src_port_start;
    uint16_t src_port_end;
    uint16_t dst_port_start;
    uint16_t dst_port_end;
    uint8_t  protocol;
    bool     proto_wildcard;
    Action   action;
    uint64_t hit_count;
};

class PacketFilter {
public:
    PacketFilter() : default_action_(Action::DROP), active_rules_count_(0) {}
    ~PacketFilter() = default;

    void SetDefaultAction(Action action) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        default_action_ = action;
    }

    Action GetDefaultAction() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return default_action_;
    }

    int AddRule(const Rule& rule) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        if (rules_.size() >= MAX_RULES) {
            return -1;
        }
        Rule r = rule;
        r.hit_count = 0;
        rules_.push_back(r);
        active_rules_count_.fetch_add(1, std::memory_order_relaxed);
        return static_cast<int>(rules_.size() - 1);
    }

    bool RemoveRule(size_t index) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        if (index >= rules_.size()) {
            return false;
        }
        rules_.erase(rules_.begin() + index);
        active_rules_count_.fetch_sub(1, std::memory_order_relaxed);
        return true;
    }

    void ClearRules() {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        rules_.clear();
        active_rules_count_.store(0, std::memory_order_relaxed);
    }

    Action Evaluate(const Packet& pkt) {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        
        for (auto& rule : rules_) {
            if ((pkt.src_ip & rule.src_mask) != (rule.src_ip & rule.src_mask)) continue;
            if ((pkt.dst_ip & rule.dst_mask) != (rule.dst_ip & rule.dst_mask)) continue;
            
            if (pkt.src_port < rule.src_port_start || pkt.src_port > rule.src_port_end) continue;
            if (pkt.dst_port < rule.dst_port_start || pkt.dst_port > rule.dst_port_end) continue;
            
            if (!rule.proto_wildcard && pkt.protocol != rule.protocol) continue;

            const_cast<Rule&>(rule).hit_count++;
            return rule.action;
        }

        return default_action_;
    }

    size_t GetRuleCount() const {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        return rules_.size();
    }

    uint64_t GetRuleHits(size_t index) {
        std::shared_lock<std::shared_mutex> lock(mutex_);
        if (index >= rules_.size()) return 0;
        return rules_[index].hit_count;
    }

    static constexpr size_t MAX_RULES = 1024;

private:
    mutable std::shared_mutex mutex_;
    std::vector<Rule> rules_;
    Action default_action_;
    std::atomic<size_t> active_rules_count_;
};

} // namespace Titan

class TestSuite {
public:
    static void RunAll() {
        std::cout << "[INFO] Starting TitanPacketFilter Exhaustive Test Suite..." << std::endl;
        
        TestUnitBoundaries();
        TestInvariants();
        TestConcurrentStress();
        TestFailureAndRecovery();

        std::cout << "[INFO] ALL TESTS PASSED SUCCESSFULLY." << std::endl;
    }

private:
    static void TestUnitBoundaries() {
        std::cout << "[RUN ] TestUnitBoundaries..." << std::endl;
        Titan::PacketFilter filter;

        // Edge case: Empty rule set defaults properly
        Titan::Packet p1{0x0A000001, 0x0A000002, 1234, 80, 6, 0, nullptr};
        assert(filter.GetDefaultAction() == Titan::Action::DROP);
        assert(filter.Evaluate(p1) == Titan::Action::DROP);

        filter.SetDefaultAction(Titan::Action::ALLOW);
        assert(filter.GetDefaultAction() == Titan::Action::ALLOW);
        assert(filter.Evaluate(p1) == Titan::Action::ALLOW);

        // Boundary: IP and Port exact matches
        Titan::Rule r1;
        r1.src_ip = 0xC0A80101; // 192.168.1.1
        r1.src_mask = 0xFFFFFFFF;
        r1.dst_ip = 0xC0A80102; // 192.168.1.2
        r1.dst_mask = 0xFFFFFFFF;
        r1.src_port_start = 1024;
        r1.src_port_end = 1024;
        r1.dst_port_start = 80;
        r1.dst_port_end = 80;
        r1.protocol = 6;
        r1.proto_wildcard = false;
        r1.action = Titan::Action::DROP;

        int idx = filter.AddRule(r1);
        assert(idx == 0);

        // Exact match packet
        Titan::Packet match_pkt{0xC0A80101, 0xC0A80102, 1024, 80, 6, 0, nullptr};
        assert(filter.Evaluate(match_pkt) == Titan::Action::DROP);

        // Off-by-one port boundary check
        Titan::Packet off_port_src{0xC0A80101, 0xC0A80102, 1025, 80, 6, 0, nullptr};
        assert(filter.Evaluate(off_port_src) == Titan::Action::ALLOW); // Falls back to default ALLOW

        Titan::Packet off_port_dst{0xC0A80101, 0xC0A80102, 1024, 81, 6, 0, nullptr};
        assert(filter.Evaluate(off_port_dst) == Titan::Action::ALLOW);

        // Subnet Mask Edge Cases (/0 wildcard)
        Titan::Rule r_subnet;
        r_subnet.src_ip = 0;
        r_subnet.src_mask = 0x00000000;
        r_subnet.dst_ip = 0;
        r_subnet.dst_mask = 0x00000000;
        r_subnet.src_port_start = 0;
        r_subnet.src_port_end = 65535;
        r_subnet.dst_port_start = 0;
        r_subnet.dst_port_end = 65535;
        r_subnet.protocol = 17;
        r_subnet.proto_wildcard = false;
        r_subnet.action = Titan::Action::REJECT;

        filter.AddRule(r_subnet);
        Titan::Packet udp_pkt{0xFFFFFFFF, 0xFFFFFFFF, 50000, 53, 17, 0, nullptr};
        assert(filter.Evaluate(udp_pkt) == Titan::Action::REJECT);

        std::cout << "[PASS] TestUnitBoundaries completed." << std::endl;
    }

    static void TestInvariants() {
        std::cout << "[RUN ] TestInvariants..." << std::endl;
        Titan::PacketFilter filter;

        // Invariant: Rule count matches additions and removals
        for (int i = 0; i < 100; ++i) {
            Titan::Rule r{};
            r.src_mask = 0xFFFFFFFF;
            r.dst_mask = 0xFFFFFFFF;
            r.src_port_end = 65535;
            r.dst_port_end = 65535;
            filter.AddRule(r);
        }
        assert(filter.GetRuleCount() == 100);

        // Invariant: Hit counts monotonically increase
        Titan::Packet p{0, 0, 0, 0, 0, 0, nullptr};
        uint64_t initial_hits = filter.GetRuleHits(0);
        filter.Evaluate(p);
        assert(filter.GetRuleHits(0) == initial_hits + 1);

        // Invariant: Deletion shifts indexes safely without corruption
        bool removed = filter.RemoveRule(0);
        assert(removed);
        assert(filter.GetRuleCount() == 99);

        filter.ClearRules();
        assert(filter.GetRuleCount() == 0);

        std::cout << "[PASS] TestInvariants completed." << std::endl;
    }

    static void TestConcurrentStress() {
        std::cout << "[RUN ] TestConcurrentStress..." << std::endl;
        Titan::PacketFilter filter;

        std::atomic<bool> start_signal{false};
        std::atomic<uint64_t> total_evaluations{0};
        const int num_threads = 16;
        const int operations_per_thread = 5000;

        std::vector<std::thread> threads;
        threads.reserve(num_threads);

        // Spawn evaluator threads
        for (int i = 0; i < num_threads / 2; ++i) {
            threads.emplace_back([&filter, &start_signal, &total_evaluations, operations_per_thread]() {
                while (!start_signal.load(std::memory_order_acquire)) {
                    std::this_thread::yield();
                }
                for (int op = 0; op < operations_per_thread; ++op) {
                    Titan::Packet p{static_cast<uint32_t>(op), 0x0A000001, static_cast<uint16_t>(op), 80, 6, 0, nullptr};
                    filter.Evaluate(p);
                    total_evaluations.fetch_add(1, std::memory_order_relaxed);
                }
            });
        }

        // Spawn modifier threads (Add/Remove rules concurrently)
        for (int i = 0; i < num_threads / 2; ++i) {
            threads.emplace_back([&filter, &start_signal, operations_per_thread]() {
                while (!start_signal.load(std::memory_order_acquire)) {
                    std::this_thread::yield();
                }
                for (int op = 0; op < operations_per_thread / 10; ++op) {
                    Titan::Rule r{};
                    r.src_mask = 0xFFFFFFFF;
                    r.dst_mask = 0xFFFFFFFF;
                    r.src_port_end = 65535;
                    r.dst_port_end = 65535;
                    int idx =