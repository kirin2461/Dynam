#ifdef HAVE_LIBWEBSOCKETS
#include "ncp_ws_tunnel.hpp"
#include <libwebsockets.h>
#include <thread>
#include <mutex>
#include <queue>
#include <atomic>
#include <chrono>
#include <cstring>
#include <algorithm>

namespace ncp {

// ---------------------------------------------------------------------------
// WSTunnel::Impl — private implementation (pimpl)
// ---------------------------------------------------------------------------
struct WSTunnel::Impl {
    WSTunnelConfig config;
    
    struct lws_context* context = nullptr;
    struct lws* wsi = nullptr;
    std::thread service_thread;
    std::atomic<bool> running{false};
    std::atomic<bool> connected{false};
    
    // Thread-safe send queue
    std::mutex send_mutex;
    std::queue<std::vector<uint8_t>> send_queue;
    
    ReceiveCallback receive_cb;
    StateCallback state_cb;
    Stats stats;
    std::mutex stats_mutex;
    
    int reconnect_count = 0;
    
    // lws protocols
    static const struct lws_protocols protocols[];
    
    // lws callback
    static int ws_callback(struct lws* wsi, enum lws_callback_reasons reason,
                           void* user, void* in, size_t len);
    
    void service_loop();
    bool connect_to_server();
    bool schedule_reconnect();
    
    // Parse URL into host, port, path, ssl flag
    struct ParsedURL {
        std::string host;
        int port = 443;
        std::string path;
        bool use_ssl = true;
    };
    ParsedURL parse_url(const std::string& url) const;
};

// ---------------------------------------------------------------------------
// Protocol table
// ---------------------------------------------------------------------------
const struct lws_protocols WSTunnel::Impl::protocols[] = {
    { "ncp-tunnel", WSTunnel::Impl::ws_callback, 0, 65536 },
    { NULL, NULL, 0, 0 }
};

// ---------------------------------------------------------------------------
// lws callback
// ---------------------------------------------------------------------------
int WSTunnel::Impl::ws_callback(struct lws* wsi,
    enum lws_callback_reasons reason, void* user, void* in, size_t len)
{
    // Retrieve Impl* stored as user-data of the lws_context
    struct lws_context* ctx = lws_get_context(wsi);
    if (!ctx) return 0;
    Impl* self = static_cast<Impl*>(lws_context_user(ctx));
    if (!self) return 0;
    
    switch (reason) {
    case LWS_CALLBACK_CLIENT_ESTABLISHED:
        self->connected = true;
        self->reconnect_count = 0;
        if (self->state_cb) self->state_cb(true);
        // Request writable if there is queued data
        {
            std::lock_guard<std::mutex> lock(self->send_mutex);
            if (!self->send_queue.empty())
                lws_callback_on_writable(wsi);
        }
        break;
        
    case LWS_CALLBACK_CLIENT_RECEIVE:
        if (self->receive_cb && in && len > 0) {
            self->receive_cb(static_cast<const uint8_t*>(in), len);
            std::lock_guard<std::mutex> lock(self->stats_mutex);
            self->stats.bytes_received += len;
            self->stats.frames_received++;
        }
        break;
        
    case LWS_CALLBACK_CLIENT_WRITEABLE: {
        std::lock_guard<std::mutex> lock(self->send_mutex);
        if (!self->send_queue.empty()) {
            auto& data = self->send_queue.front();
            // LWS_PRE padding required by libwebsockets before payload
            std::vector<uint8_t> buf(LWS_PRE + data.size());
            std::memcpy(buf.data() + LWS_PRE, data.data(), data.size());
            int written = lws_write(wsi, buf.data() + LWS_PRE,
                                    data.size(), LWS_WRITE_BINARY);
            if (written > 0) {
                std::lock_guard<std::mutex> slock(self->stats_mutex);
                self->stats.bytes_sent += static_cast<uint64_t>(written);
                self->stats.frames_sent++;
            }
            self->send_queue.pop();
            
            // If more data pending, request another writable callback
            if (!self->send_queue.empty())
                lws_callback_on_writable(wsi);
        }
        break;
    }
    
    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
    case LWS_CALLBACK_CLIENT_CLOSED:
        self->connected = false;
        self->wsi = nullptr;
        if (self->state_cb) self->state_cb(false);
        self->schedule_reconnect();
        break;
        
    default:
        break;
    }
    return 0;
}

// ---------------------------------------------------------------------------
// URL parser (minimal)
// ---------------------------------------------------------------------------
WSTunnel::Impl::ParsedURL
WSTunnel::Impl::parse_url(const std::string& url) const
{
    ParsedURL parsed;
    std::string u = url;
    
    // Detect scheme
    if (u.rfind("wss://", 0) == 0) {
        parsed.use_ssl = true;
        parsed.port = 443;
        u = u.substr(6);
    } else if (u.rfind("ws://", 0) == 0) {
        parsed.use_ssl = false;
        parsed.port = 80;
        u = u.substr(5);
    }
    
    // Split host[:port] and path
    auto slash = u.find('/');
    std::string host_port = (slash != std::string::npos) ? u.substr(0, slash) : u;
    parsed.path = (slash != std::string::npos) ? u.substr(slash) : "/";
    
    auto colon = host_port.rfind(':');
    if (colon != std::string::npos) {
        parsed.host = host_port.substr(0, colon);
        parsed.port = std::stoi(host_port.substr(colon + 1));
    } else {
        parsed.host = host_port;
    }
    
    return parsed;
}

// ---------------------------------------------------------------------------
// Service loop (runs in its own thread)
// ---------------------------------------------------------------------------
void WSTunnel::Impl::service_loop()
{
    while (running.load()) {
        if (context) {
            lws_service(context, 50);  // 50 ms timeout
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

// ---------------------------------------------------------------------------
// Connect / reconnect
// ---------------------------------------------------------------------------
bool WSTunnel::Impl::connect_to_server()
{
    auto parsed = parse_url(config.server_url);
    std::string path = config.path.empty() ? parsed.path : config.path;
    
    struct lws_client_connect_info cci = {};
    cci.context = context;
    cci.address = parsed.host.c_str();
    cci.port    = parsed.port;
    cci.path    = path.c_str();
    cci.host    = parsed.host.c_str();
    cci.origin  = parsed.host.c_str();
    cci.protocol = protocols[0].name;
    
    if (parsed.use_ssl) {
        cci.ssl_connection = LCCSCF_USE_SSL;
        if (!config.verify_peer)
            cci.ssl_connection |= LCCSCF_ALLOW_SELFSIGNED
                               | LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;
    }
    
    // SNI override for domain fronting
    if (!config.sni_override.empty())
        cci.host = config.sni_override.c_str();
    
    wsi = lws_client_connect_via_info(&cci);
    return wsi != nullptr;
}

bool WSTunnel::Impl::schedule_reconnect()
{
    if (!running.load()) return false;
    if (reconnect_count >= config.max_reconnect_attempts) return false;
    
    reconnect_count++;
    {
        std::lock_guard<std::mutex> lock(stats_mutex);
        stats.reconnects++;
    }
    
    // Exponential backoff: delay * 2^(attempt-1), capped at 30 s
    int delay = config.reconnect_delay_ms * (1 << std::min(reconnect_count - 1, 5));
    delay = std::min(delay, 30000);
    
    std::thread([this, delay]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(delay));
        if (running.load())
            connect_to_server();
    }).detach();
    
    return true;
}

// ---------------------------------------------------------------------------
// WSTunnel public API
// ---------------------------------------------------------------------------
WSTunnel::WSTunnel() : impl_(std::make_unique<Impl>()) {}
WSTunnel::~WSTunnel() { stop(); }

bool WSTunnel::initialize(const WSTunnelConfig& config)
{
    impl_->config = config;
    
    struct lws_context_creation_info info = {};
    info.port = CONTEXT_PORT_NO_LISTEN;  // client-only
    info.protocols = Impl::protocols;
    info.user = impl_.get();             // store Impl* for the callback
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    
    if (!config.ca_cert_path.empty())
        info.client_ssl_ca_filepath = config.ca_cert_path.c_str();
    
    // Compression
    struct lws_extension exts[] = {
        { "permessage-deflate",
          lws_extension_callback_pm_deflate,
          "permessage-deflate; client_max_window_bits" },
        { NULL, NULL, NULL }
    };
    if (config.enable_compression)
        info.extensions = exts;
    
    impl_->context = lws_create_context(&info);
    return impl_->context != nullptr;
}

bool WSTunnel::start()
{
    if (!impl_->context) return false;
    impl_->running = true;
    
    // Connect to relay server
    if (!impl_->connect_to_server()) {
        impl_->running = false;
        return false;
    }
    
    // Start service thread
    impl_->service_thread = std::thread(&Impl::service_loop, impl_.get());
    return true;
}

void WSTunnel::stop()
{
    impl_->running = false;
    impl_->connected = false;
    
    if (impl_->service_thread.joinable())
        impl_->service_thread.join();
    
    if (impl_->context) {
        lws_context_destroy(impl_->context);
        impl_->context = nullptr;
    }
    impl_->wsi = nullptr;
}

bool WSTunnel::is_connected() const { return impl_->connected.load(); }

bool WSTunnel::send(const uint8_t* data, size_t len)
{
    if (!impl_->connected.load() || !data || len == 0)
        return false;
    
    {
        std::lock_guard<std::mutex> lock(impl_->send_mutex);
        impl_->send_queue.emplace(data, data + len);
    }
    
    // Request writable callback so the queue gets drained
    if (impl_->wsi)
        lws_callback_on_writable(impl_->wsi);
    
    return true;
}

void WSTunnel::set_receive_callback(ReceiveCallback cb) { impl_->receive_cb = std::move(cb); }
void WSTunnel::set_state_callback(StateCallback cb)     { impl_->state_cb = std::move(cb); }

WSTunnel::Stats WSTunnel::get_stats() const
{
    std::lock_guard<std::mutex> lock(impl_->stats_mutex);
    return impl_->stats;
}

} // namespace ncp
#endif // HAVE_LIBWEBSOCKETS
