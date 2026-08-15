// ═══════════════════════════════════════════════════════════════════════════
// NCP AutoPilot — adaptive, self-learning DPI-bypass strategy engine.
// See ncp_autopilot.hpp for the design contract.
// ═══════════════════════════════════════════════════════════════════════════

#include "ncp_autopilot.hpp"
#include "ncp_blockcheck.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>
#include <thread>

#ifdef _WIN32
#include <direct.h>
#include <cstdlib>
#else
#include <sys/stat.h>
#include <cstdlib>
#endif

namespace ncp {

// ─────────────────────────────────────────────────────────────────────────────
// Minimal tolerant JSON (reads what we write; unknown/truncated → parse error)
// ─────────────────────────────────────────────────────────────────────────────
namespace {

struct JVal {
    enum Type { NUL, BOOL, NUM, STR, OBJ, ARR } type = NUL;
    bool b = false;
    double num = 0.0;
    std::string str;
    std::map<std::string, JVal> obj;
    std::vector<JVal> arr;

    const JVal* find(const std::string& key) const {
        if (type != OBJ) return nullptr;
        auto it = obj.find(key);
        return it == obj.end() ? nullptr : &it->second;
    }
    double get_num(const std::string& key, double dflt = 0.0) const {
        const JVal* v = find(key);
        return (v && v->type == NUM) ? v->num : dflt;
    }
    std::string get_str(const std::string& key) const {
        const JVal* v = find(key);
        return (v && v->type == STR) ? v->str : std::string();
    }
    bool get_bool(const std::string& key, bool dflt = false) const {
        const JVal* v = find(key);
        return (v && v->type == BOOL) ? v->b : dflt;
    }
};

class JParser {
public:
    explicit JParser(const std::string& s) : s_(s) {}

    bool parse(JVal* out) {
        skip_ws();
        if (!value(out)) return false;
        skip_ws();
        return pos_ == s_.size();
    }

private:
    const std::string& s_;
    size_t pos_ = 0;
    int depth_ = 0;

    void skip_ws() {
        while (pos_ < s_.size() &&
               (s_[pos_] == ' ' || s_[pos_] == '\t' || s_[pos_] == '\n' || s_[pos_] == '\r'))
            ++pos_;
    }
    bool value(JVal* out) {
        if (++depth_ > 32) return false;  // recursion guard
        skip_ws();
        if (pos_ >= s_.size()) return false;
        char c = s_[pos_];
        bool ok = false;
        if (c == '{') ok = object(out);
        else if (c == '[') ok = array(out);
        else if (c == '"') { out->type = JVal::STR; ok = string(&out->str); }
        else if (c == 't') ok = literal("true") && (out->type = JVal::BOOL, out->b = true, true);
        else if (c == 'f') ok = literal("false") && (out->type = JVal::BOOL, out->b = false, true);
        else if (c == 'n') ok = literal("null") && (out->type = JVal::NUL, true);
        else ok = number(out);
        --depth_;
        return ok;
    }
    bool literal(const char* lit) {
        size_t n = std::strlen(lit);
        if (s_.compare(pos_, n, lit) != 0) return false;
        pos_ += n;
        return true;
    }
    bool number(JVal* out) {
        size_t start = pos_;
        if (pos_ < s_.size() && s_[pos_] == '-') ++pos_;
        while (pos_ < s_.size() && (isdigit((unsigned char)s_[pos_]) || s_[pos_] == '.' ||
                                    s_[pos_] == 'e' || s_[pos_] == 'E' ||
                                    s_[pos_] == '+' || s_[pos_] == '-'))
            ++pos_;
        if (pos_ == start) return false;
        try {
            out->num = std::stod(s_.substr(start, pos_ - start));
        } catch (...) { return false; }
        out->type = JVal::NUM;
        return true;
    }
    bool string(std::string* out) {
        if (s_[pos_] != '"') return false;
        ++pos_;
        out->clear();
        while (pos_ < s_.size()) {
            char c = s_[pos_++];
            if (c == '"') return true;
            if (c == '\\') {
                if (pos_ >= s_.size()) return false;
                char e = s_[pos_++];
                switch (e) {
                    case 'n': out->push_back('\n'); break;
                    case 't': out->push_back('\t'); break;
                    case 'r': out->push_back('\r'); break;
                    case 'u':  // skip \uXXXX (we never emit non-ASCII keys/values)
                        if (pos_ + 4 > s_.size()) return false;
                        pos_ += 4;
                        out->push_back('?');
                        break;
                    default: out->push_back(e); break;
                }
            } else {
                out->push_back(c);
            }
        }
        return false;  // unterminated
    }
    bool object(JVal* out) {
        ++pos_;  // '{'
        out->type = JVal::OBJ;
        skip_ws();
        if (pos_ < s_.size() && s_[pos_] == '}') { ++pos_; return true; }
        while (pos_ < s_.size()) {
            skip_ws();
            std::string key;
            if (!string(&key)) return false;
            skip_ws();
            if (pos_ >= s_.size() || s_[pos_] != ':') return false;
            ++pos_;
            JVal v;
            if (!value(&v)) return false;
            out->obj[key] = std::move(v);
            skip_ws();
            if (pos_ >= s_.size()) return false;
            if (s_[pos_] == ',') { ++pos_; continue; }
            if (s_[pos_] == '}') { ++pos_; return true; }
            return false;
        }
        return false;
    }
    bool array(JVal* out) {
        ++pos_;  // '['
        out->type = JVal::ARR;
        skip_ws();
        if (pos_ < s_.size() && s_[pos_] == ']') { ++pos_; return true; }
        while (pos_ < s_.size()) {
            JVal v;
            if (!value(&v)) return false;
            out->arr.push_back(std::move(v));
            skip_ws();
            if (pos_ >= s_.size()) return false;
            if (s_[pos_] == ',') { ++pos_; continue; }
            if (s_[pos_] == ']') { ++pos_; return true; }
            return false;
        }
        return false;
    }
};

std::string ap_json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if ((unsigned char)c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

int64_t ap_now() { return static_cast<int64_t>(std::time(nullptr)); }

void ap_mkdir_parent(const std::string& path) {
    // create the parent directory of `path` (single level deep is enough:
    // ~/.ncp or %APPDATA%\ncp — parents always exist)
    size_t slash = path.find_last_of("/\\");
    if (slash == std::string::npos) return;
    std::string dir = path.substr(0, slash);
    if (dir.empty()) return;
#ifdef _WIN32
    _mkdir(dir.c_str());
#else
    mkdir(dir.c_str(), 0700);
#endif
}

} // anonymous namespace

// ─────────────────────────────────────────────────────────────────────────────
// Impl
// ─────────────────────────────────────────────────────────────────────────────
class AutoPilot::Impl {
public:
    Config cfg;
    mutable std::mutex mu;                 // guards db + pending_fail
    std::map<std::string, AutoPilotRecord> db;
    std::map<std::string, uint32_t> pending_fail;  // unknown-host failure counters
    std::atomic<bool> enabled{false};
    std::atomic<bool> running{false};
    std::atomic<bool> learn_busy{false};
    std::thread janitor;

    ~Impl() { stop_janitor(); }

    // ── locked helpers (call with mu held) ──
    AutoPilotRecord* find_locked(const std::string& host) {
        auto it = db.find(host);
        return it == db.end() ? nullptr : &it->second;
    }
    // longest-suffix match: exact, then strip leftmost labels
    AutoPilotRecord* match_locked(const std::string& host) {
        if (AutoPilotRecord* r = find_locked(host)) return r;
        size_t dot = host.find('.');
        while (dot != std::string::npos && dot + 1 < host.size()) {
            std::string parent = host.substr(dot + 1);
            if (AutoPilotRecord* r = find_locked(parent)) return r;
            dot = parent.empty() ? std::string::npos : host.find('.', dot + 1);
        }
        return nullptr;
    }
    void evict_locked() {
        while (db.size() > cfg.max_records) {
            auto oldest = db.begin();
            for (auto it = db.begin(); it != db.end(); ++it)
                if (it->second.last_outcome < oldest->second.last_outcome) oldest = it;
            db.erase(oldest);
        }
    }

    bool save_locked() const {
        if (cfg.db_path.empty()) return false;
        ap_mkdir_parent(cfg.db_path);
        std::string tmp = cfg.db_path + ".tmp";
        {
            std::ofstream f(tmp, std::ios::trunc);
            if (!f) return false;
            f << serialize_locked();
            if (!f) { std::remove(tmp.c_str()); return false; }
        }
        if (std::rename(tmp.c_str(), cfg.db_path.c_str()) != 0) {
            // Windows: rename fails if target exists
            std::remove(cfg.db_path.c_str());
            if (std::rename(tmp.c_str(), cfg.db_path.c_str()) != 0) {
                std::remove(tmp.c_str());
                return false;
            }
        }
        return true;
    }

    std::string serialize_locked() const {
        std::ostringstream j;
        j << "{\n  \"version\": 1,\n  \"enabled\": " << (enabled.load() ? "true" : "false")
          << ",\n  \"records\": {\n";
        bool first = true;
        for (const auto& kv : db) {
            const AutoPilotRecord& r = kv.second;
            if (!first) j << ",\n";
            first = false;
            j << "    \"" << ap_json_escape(r.host) << "\": {"
              << "\"strategy\": \"" << ap_json_escape(r.strategy.name) << "\", "
              << "\"positions\": [";
            for (size_t i = 0; i < r.strategy.positions.size(); ++i) {
                j << (i ? ", " : "") << "{\"type\": "
                  << static_cast<int>(r.strategy.positions[i].type) << ", \"offset\": "
                  << r.strategy.positions[i].offset << "}";
            }
            j << "], \"host_case\": " << (r.strategy.host_case ? "true" : "false")
              << ", \"successes\": " << r.successes
              << ", \"failures\": " << r.failures
              << ", \"consec_failures\": " << r.consec_failures
              << ", \"ewma_latency_ms\": " << r.ewma_latency_ms
              << ", \"last_learned\": " << r.last_learned
              << ", \"last_outcome\": " << r.last_outcome
              << ", \"cooldown\": " << r.relearn_cooldown_sec
              << ", \"degraded\": " << (r.degraded ? "true" : "false") << "}";
        }
        j << "\n  }\n}\n";
        return j.str();
    }

    bool load_from_disk() {
        std::ifstream f(cfg.db_path);
        if (!f) return false;  // missing = empty DB
        std::stringstream ss;
        ss << f.rdbuf();
        JVal root;
        if (!JParser(ss.str()).parse(&root)) return false;  // corrupt = empty DB

        enabled.store(root.get_bool("enabled", false));
        const JVal* recs = root.find("records");
        if (recs && recs->type == JVal::OBJ) {
            std::lock_guard<std::mutex> lk(mu);
            for (const auto& kv : recs->obj) {
                const JVal& v = kv.second;
                AutoPilotRecord r;
                r.host = kv.first;
                r.strategy.name = v.get_str("strategy");
                if (r.strategy.name.empty()) continue;
                const JVal* pos = v.find("positions");
                if (pos && pos->type == JVal::ARR) {
                    for (const auto& p : pos->arr) {
                        DPI::ZSplitPos sp;
                        sp.type = static_cast<DPI::ZSplitPosType>(
                            static_cast<int>(p.get_num("type", 0)));
                        sp.offset = static_cast<int>(p.get_num("offset", 0));
                        r.strategy.positions.push_back(sp);
                    }
                }
                r.strategy.host_case = v.get_bool("host_case", false);
                r.successes = static_cast<uint64_t>(v.get_num("successes", 0));
                r.failures = static_cast<uint64_t>(v.get_num("failures", 0));
                r.consec_failures = static_cast<uint32_t>(v.get_num("consec_failures", 0));
                r.ewma_latency_ms = v.get_num("ewma_latency_ms", 0.0);
                r.last_learned = static_cast<int64_t>(v.get_num("last_learned", 0));
                r.last_outcome = static_cast<int64_t>(v.get_num("last_outcome", 0));
                r.relearn_cooldown_sec = v.get_num("cooldown", 120.0);
                if (r.relearn_cooldown_sec < 30.0) r.relearn_cooldown_sec = 120.0;
                r.degraded = v.get_bool("degraded", false);
                db[r.host] = std::move(r);
            }
        }
        return true;
    }

    // ── strategy conversion (blockcheck winner → socket-level plan) ──
    static AutoPilotStrategy strategy_from_report(const BlockcheckReport& rep) {
        AutoPilotStrategy st;
        st.name = rep.best_strategy;
        if (st.name.empty() || st.name == "direct") {
            st.name = "direct";  // passthrough: no splits
            return st;
        }
        if (rep.best_uses_chain) {
            const DPI::ZapretChain& c = rep.best_chain;
            if (c.phase2 == DPI::ZDesyncPhase2::MULTISPLIT ||
                c.phase2 == DPI::ZDesyncPhase2::MULTIDISORDER ||
                c.phase2 == DPI::ZDesyncPhase2::FAKEDSPLIT ||
                c.phase2 == DPI::ZDesyncPhase2::FAKEDDISORDER ||
                c.phase2 == DPI::ZDesyncPhase2::HOSTFAKESPLIT) {
                st.positions = c.split_positions;
                if (st.positions.empty())
                    st.positions.push_back(DPI::ZSplitPos{DPI::ZSplitPosType::NUMERIC, 1});
                if (c.phase2 == DPI::ZDesyncPhase2::HOSTFAKESPLIT)
                    st.positions.push_back(DPI::ZSplitPos{DPI::ZSplitPosType::MIDSLD, 0});
            } else {
                st.positions.push_back(DPI::ZSplitPos{DPI::ZSplitPosType::NUMERIC, 2});
            }
        } else {
            const DPI::DPIConfig& b = rep.best_config;
            if (b.enable_multi_layer_split && !b.split_positions.empty()) {
                for (int p : b.split_positions)
                    st.positions.push_back(DPI::ZSplitPos{DPI::ZSplitPosType::NUMERIC, p});
            } else if (b.enable_tcp_split && b.split_position > 0) {
                st.positions.push_back(
                    DPI::ZSplitPos{DPI::ZSplitPosType::NUMERIC, b.split_position});
            }
            if (b.split_at_sni)
                st.positions.push_back(DPI::ZSplitPos{DPI::ZSplitPosType::HOST, 0});
            st.host_case = b.enable_host_case;
        }
        return st;
    }

    // ── janitor ──
    void janitor_loop(AutoPilot* self);
    void stop_janitor() {
        running.store(false);
        if (janitor.joinable()) janitor.join();
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// AutoPilot public API
// ─────────────────────────────────────────────────────────────────────────────
AutoPilot::AutoPilot() : impl_(std::make_unique<Impl>()) {}
AutoPilot::~AutoPilot() = default;

std::string AutoPilot::normalize_host(const std::string& host_in) {
    std::string h = host_in;
    // strip brackets (IPv6 literal) — not a learning target, but be safe
    if (!h.empty() && h.front() == '[' && h.back() == ']')
        h = h.substr(1, h.size() - 2);
    while (!h.empty() && h.back() == '.') h.pop_back();
    std::transform(h.begin(), h.end(), h.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return h;
}

std::string AutoPilot::default_db_path() {
#ifdef _WIN32
    const char* appdata = std::getenv("APPDATA");
    if (appdata && *appdata) return std::string(appdata) + "\\ncp\\autopilot.json";
    return "autopilot.json";
#else
    const char* home = std::getenv("HOME");
    if (home && *home) return std::string(home) + "/.ncp/autopilot.json";
    return "autopilot.json";
#endif
}

bool AutoPilot::load(const Config& cfg) {
    impl_->cfg = cfg;
    if (impl_->cfg.db_path.empty()) impl_->cfg.db_path = default_db_path();
    if (impl_->cfg.max_records == 0) impl_->cfg.max_records = 512;
    impl_->load_from_disk();
    return true;
}

bool AutoPilot::save() const {
    std::lock_guard<std::mutex> lk(impl_->mu);
    return impl_->save_locked();
}

bool AutoPilot::lookup(const std::string& host, AutoPilotStrategy* out) const {
    std::lock_guard<std::mutex> lk(impl_->mu);
    const AutoPilotRecord* r =
        const_cast<Impl*>(impl_.get())->match_locked(normalize_host(host));
    if (!r || r->degraded || r->strategy.name == "unknown") return false;
    if (out) *out = r->strategy;
    return true;
}

void AutoPilot::report_success(const std::string& host_in, double latency_ms) {
    std::string host = normalize_host(host_in);
    std::lock_guard<std::mutex> lk(impl_->mu);
    AutoPilotRecord* r = impl_->match_locked(host);
    if (!r) return;  // unknown host: keep the DB clean
    r->successes++;
    r->consec_failures = 0;
    r->last_outcome = ap_now();
    if (latency_ms > 0.0) {
        double a = impl_->cfg.ewma_alpha;
        r->ewma_latency_ms = (r->ewma_latency_ms <= 0.0)
                                 ? latency_ms
                                 : (1.0 - a) * r->ewma_latency_ms + a * latency_ms;
    }
    if (r->degraded) {
        // live traffic succeeded through a fallback — the host is reachable,
        // keep degraded flag so the janitor still refreshes the strategy,
        // but reflect reachability in stats only.
    }
}

void AutoPilot::report_failure(const std::string& host_in, const std::string& /*reason*/) {
    std::string host = normalize_host(host_in);
    bool changed = false;
    {
        std::lock_guard<std::mutex> lk(impl_->mu);
        AutoPilotRecord* r = impl_->match_locked(host);
        if (!r) {
            uint32_t n = ++impl_->pending_fail[host];
            if (n >= impl_->cfg.degrade_threshold) {
                AutoPilotRecord rec;
                rec.host = host;
                rec.strategy.name = "unknown";
                rec.failures = n;
                rec.consec_failures = n;
                rec.last_outcome = ap_now();
                rec.degraded = true;  // janitor will learn it
                impl_->db[host] = rec;
                impl_->pending_fail.erase(host);
                impl_->evict_locked();
                changed = true;
            }
        } else {
            r->failures++;
            r->consec_failures++;
            r->last_outcome = ap_now();
            if (!r->degraded && r->consec_failures >= impl_->cfg.degrade_threshold) {
                r->degraded = true;
                changed = true;
            }
        }
    }
    if (changed) save();
}

bool AutoPilot::learn(const std::string& host_in, std::string* learned_name) {
    std::string host = normalize_host(host_in);
    if (host.empty()) return false;
    // one learn at a time (probing spins up temp proxies)
    if (impl_->learn_busy.exchange(true)) return false;
    struct BusyGuard {
        std::atomic<bool>& f;
        ~BusyGuard() { f.store(false); }
    } guard{impl_->learn_busy};

    int timeout_ms = impl_->cfg.probe_timeout_ms;

    // ── probe WITHOUT holding the mutex ──
    BlockChecker checker;
    BlockChecker::Config bcfg;
    bcfg.domains = {host};
    bcfg.timeout_ms = timeout_ms;
    bcfg.use_doh = impl_->cfg.use_doh;
    BlockcheckReport rep = checker.run(bcfg);

    // A winner is real only if it actually probed successfully. Note: "direct"
    // winning legitimately means no bypass is needed (passthrough record).
    bool found = false;
    for (const auto& sr : rep.results) {
        if (sr.strategy == rep.best_strategy && sr.success_count > 0) found = true;
    }

    AutoPilotStrategy st = Impl::strategy_from_report(rep);
    if (!found) st.name = "unknown";

    // ── commit result ──
    {
        std::lock_guard<std::mutex> lk(impl_->mu);
        AutoPilotRecord& r = impl_->db[host];
        r.host = host;
        if (found) {
            r.strategy = st;
            r.degraded = false;
            r.consec_failures = 0;
            r.relearn_cooldown_sec = 120.0;
            if (learned_name) *learned_name = st.name;
        } else {
            r.degraded = true;
            r.relearn_cooldown_sec = std::min(r.relearn_cooldown_sec * 2.0, 3600.0);
        }
        r.last_learned = ap_now();
        r.last_outcome = ap_now();
        impl_->evict_locked();
    }
    save();
    return found;
}

void AutoPilot::reset(const std::string& host_in) {
    {
        std::lock_guard<std::mutex> lk(impl_->mu);
        if (host_in.empty()) {
            impl_->db.clear();
            impl_->pending_fail.clear();
        } else {
            impl_->db.erase(normalize_host(host_in));
        }
    }
    save();
}

std::vector<AutoPilotRecord> AutoPilot::records() const {
    std::lock_guard<std::mutex> lk(impl_->mu);
    std::vector<AutoPilotRecord> out;
    out.reserve(impl_->db.size());
    for (const auto& kv : impl_->db) out.push_back(kv.second);
    return out;
}

std::string AutoPilot::to_json() const {
    std::lock_guard<std::mutex> lk(impl_->mu);
    return impl_->serialize_locked();
}

void AutoPilot::set_enabled(bool en) {
    impl_->enabled.store(en);
    save();
}
bool AutoPilot::enabled() const { return impl_->enabled.load(); }
bool AutoPilot::running() const { return impl_->running.load(); }

void AutoPilot::Impl::janitor_loop(AutoPilot* self) {
    while (running.load()) {
        for (int i = 0; i < 10 && running.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(500));

        if (!running.load()) break;
        if (!cfg.background_relearn) continue;

        // pick ONE degraded host with recent traffic and expired cooldown
        std::string candidate;
        int64_t now = ap_now();
        {
            std::lock_guard<std::mutex> lk(mu);
            for (const auto& kv : db) {
                const AutoPilotRecord& r = kv.second;
                if (!r.degraded) continue;
                if (now - r.last_outcome > 600) continue;          // no recent traffic
                if (now - r.last_learned < r.relearn_cooldown_sec) continue;
                candidate = r.host;
                break;
            }
        }
        if (!candidate.empty()) self->learn(candidate);
    }
}

void AutoPilot::start() {
    if (impl_->running.exchange(true)) return;
    impl_->janitor = std::thread(&Impl::janitor_loop, impl_.get(), this);
}

void AutoPilot::stop() { impl_->stop_janitor(); }

} // namespace ncp
