#include "ncp_dpi_detector.hpp"
#include "ncp_hostlist.hpp"

#include <fstream>
#include <chrono>

namespace ncp {

DpiDetector::DpiDetector(size_t ring_capacity, int timeout_threshold)
    : capacity_(ring_capacity ? ring_capacity : 1),
      timeout_threshold_(timeout_threshold < 1 ? 1 : timeout_threshold) {}

void DpiDetector::set_event_callback(EventCallback cb) {
    std::lock_guard<std::mutex> lk(mu_);
    cb_ = std::move(cb);
}

void DpiDetector::set_log_file(const std::string& path) {
    std::lock_guard<std::mutex> lk(mu_);
    log_path_ = path;
}

const char* DpiDetector::kind_to_string(EventKind k) {
    switch (k) {
        case EventKind::RST_INJECTION:  return "rst_injection";
        case EventKind::TIMEOUT_BLOCK:  return "timeout_block";
        case EventKind::TCP_RESET_PRE:  return "tcp_reset_pre";
        case EventKind::BLOCK_CLEARED:  return "block_cleared";
    }
    return "unknown";
}

std::string DpiDetector::event_to_json(const Event& e) {
    auto esc = [](const std::string& s) {
        std::string o;
        for (char c : s) {
            if (c == '"' || c == '\\') { o.push_back('\\'); o.push_back(c); }
            else if (c == '\n') o += "\\n";
            else o.push_back(c);
        }
        return o;
    };
    return std::string("{\"kind\":\"") + kind_to_string(e.kind) +
           "\",\"host\":\"" + esc(e.host) +
           "\",\"detail\":\"" + esc(e.detail) +
           "\",\"ts\":" + std::to_string(e.ts_unix) + "}";
}

static uint64_t now_unix() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

void DpiDetector::emit(Event&& e) {
    EventCallback cb;
    std::string log_line;
    {
        std::lock_guard<std::mutex> lk(mu_);
        e.ts_unix = now_unix();
        kind_counts_[static_cast<int>(e.kind)]++;
        total_++;
        if (ring_.size() >= capacity_) ring_.pop_front();
        ring_.push_back(e);
        if (!log_path_.empty()) log_line = event_to_json(e);
        cb = cb_;
    }
    if (!log_line.empty()) {
        std::ofstream f;
        // re-read path under lock-free assumption: path rarely changes
        std::lock_guard<std::mutex> lk(mu_);
        if (!log_path_.empty()) {
            f.open(log_path_, std::ios::app);
            if (f.is_open()) f << log_line << '\n';
        }
    }
    if (cb) cb(e);
}

void DpiDetector::on_connect_reset(const std::string& host_in) {
    const std::string host = HostlistMatcher::normalize(host_in);
    if (host.empty()) return;
    {
        std::lock_guard<std::mutex> lk(mu_);
        hosts_[host].blocked = true;
    }
    Event ev{EventKind::TCP_RESET_PRE, host, "connection reset by peer during connect", 0};
    emit(std::move(ev));
}

void DpiDetector::on_reset_after_hello(const std::string& host_in) {
    const std::string host = HostlistMatcher::normalize(host_in);
    if (host.empty()) return;
    {
        std::lock_guard<std::mutex> lk(mu_);
        hosts_[host].blocked = true;
    }
    Event ev{EventKind::RST_INJECTION, host,
             "RST received after TLS ClientHello before any application data", 0};
    emit(std::move(ev));
}

void DpiDetector::on_timeout(const std::string& host_in) {
    const std::string host = HostlistMatcher::normalize(host_in);
    if (host.empty()) return;
    bool fire = false;
    int count = 0;
    {
        std::lock_guard<std::mutex> lk(mu_);
        HostState& st = hosts_[host];
        count = ++st.consecutive_timeouts;
        if (count >= timeout_threshold_ && !st.blocked) {
            st.blocked = true;
            fire = true;
        }
    }
    if (fire) {
        Event ev{EventKind::TIMEOUT_BLOCK, host,
                 std::to_string(count) + " consecutive timeouts", 0};
        emit(std::move(ev));
    }
}

void DpiDetector::on_success(const std::string& host_in) {
    const std::string host = HostlistMatcher::normalize(host_in);
    if (host.empty()) return;
    bool cleared = false;
    {
        std::lock_guard<std::mutex> lk(mu_);
        HostState& st = hosts_[host];
        st.consecutive_timeouts = 0;
        if (st.blocked) {
            st.blocked = false;
            cleared = true;
        }
    }
    if (cleared) {
        Event ev{EventKind::BLOCK_CLEARED, host, "host reachable again", 0};
        emit(std::move(ev));
    }
}

std::vector<DpiDetector::Event> DpiDetector::recent_events(size_t max_count) const {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<Event> out;
    const size_t n = std::min(max_count, ring_.size());
    out.reserve(n);
    for (size_t i = ring_.size() - n; i < ring_.size(); ++i) out.push_back(ring_[i]);
    return out;
}

size_t DpiDetector::total_events() const {
    std::lock_guard<std::mutex> lk(mu_);
    return total_;
}

size_t DpiDetector::events_of_kind(EventKind k) const {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = kind_counts_.find(static_cast<int>(k));
    return it == kind_counts_.end() ? 0 : it->second;
}

std::vector<std::string> DpiDetector::blocked_hosts() const {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<std::string> out;
    for (const auto& kv : hosts_)
        if (kv.second.blocked) out.push_back(kv.first);
    return out;
}

} // namespace ncp
