#define NCP_PCAP_DYN_IMPL
#include "ncp_pcap_dyn.hpp"

#if defined(_WIN32) && defined(HAVE_PCAP)

#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>

namespace ncp {
namespace pcapdyn {
namespace {

struct Api {
    HMODULE h = nullptr;
    decltype(&pcap_findalldevs) findalldevs = nullptr;
    decltype(&pcap_freealldevs) freealldevs = nullptr;
    decltype(&pcap_open_live)   open_live   = nullptr;
    decltype(&pcap_close)       close_      = nullptr;
    decltype(&pcap_sendpacket)  sendpacket  = nullptr;
    decltype(&pcap_geterr)      geterr      = nullptr;
    decltype(&pcap_datalink)    datalink    = nullptr;
    decltype(&pcap_next_ex)     next_ex     = nullptr;
};

Api& api() {
    static Api a;
    return a;
}

HMODULE load_wpcap() {
    // WinPcap or Npcap in "WinPcap API-compatible mode" (System32).
    if (HMODULE h = ::LoadLibraryA("wpcap.dll")) return h;
    // Native Npcap: %SystemRoot%\System32\Npcap\wpcap.dll
    // (GetSystemDirectory maps to SysWOW64 for 32-bit processes, matching
    //  Npcap's 32-bit DLL location automatically.)
    char sysdir[MAX_PATH] = {0};
    UINT n = ::GetSystemDirectoryA(sysdir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return nullptr;
    std::string path = std::string(sysdir) + "\\Npcap\\wpcap.dll";
    return ::LoadLibraryExA(path.c_str(), nullptr,
                            LOAD_WITH_ALTERED_SEARCH_PATH);
}

bool resolved() {
    static std::once_flag flag;
    static bool ok = false;
    std::call_once(flag, [] {
        Api& a = api();
        a.h = load_wpcap();
        if (!a.h) return;
        a.findalldevs = reinterpret_cast<decltype(a.findalldevs)>(
            ::GetProcAddress(a.h, "pcap_findalldevs"));
        a.freealldevs = reinterpret_cast<decltype(a.freealldevs)>(
            ::GetProcAddress(a.h, "pcap_freealldevs"));
        a.open_live = reinterpret_cast<decltype(a.open_live)>(
            ::GetProcAddress(a.h, "pcap_open_live"));
        a.close_ = reinterpret_cast<decltype(a.close_)>(
            ::GetProcAddress(a.h, "pcap_close"));
        a.sendpacket = reinterpret_cast<decltype(a.sendpacket)>(
            ::GetProcAddress(a.h, "pcap_sendpacket"));
        a.geterr = reinterpret_cast<decltype(a.geterr)>(
            ::GetProcAddress(a.h, "pcap_geterr"));
        a.datalink = reinterpret_cast<decltype(a.datalink)>(
            ::GetProcAddress(a.h, "pcap_datalink"));
        a.next_ex = reinterpret_cast<decltype(a.next_ex)>(
            ::GetProcAddress(a.h, "pcap_next_ex"));
        ok = a.findalldevs && a.freealldevs && a.open_live && a.close_ &&
             a.sendpacket && a.geterr && a.datalink && a.next_ex;
    });
    return ok;
}

void fill_errbuf(char* errbuf) {
    if (errbuf) {
        std::strncpy(errbuf,
                     "wpcap.dll (Npcap/WinPcap) not found or incompatible",
                     PCAP_ERRBUF_SIZE - 1);
        errbuf[PCAP_ERRBUF_SIZE - 1] = '\0';
    }
}

} // namespace

bool available() { return resolved(); }

int findalldevs(pcap_if_t** alldevs, char* errbuf) {
    if (!resolved()) { fill_errbuf(errbuf); return -1; }
    return api().findalldevs(alldevs, errbuf);
}

void freealldevs(pcap_if_t* alldevs) {
    if (resolved()) api().freealldevs(alldevs);
}

pcap_t* open_live(const char* device, int snaplen, int promisc, int to_ms,
                  char* errbuf) {
    if (!resolved()) { fill_errbuf(errbuf); return nullptr; }
    return api().open_live(device, snaplen, promisc, to_ms, errbuf);
}

void close(pcap_t* p) {
    if (p && resolved()) api().close_(p);
}

int sendpacket(pcap_t* p, const unsigned char* buf, int size) {
    if (!resolved()) return -1;
    return api().sendpacket(p, buf, size);
}

char* geterr(pcap_t* p) {
    if (!resolved())
        return const_cast<char*>("wpcap.dll (Npcap/WinPcap) unavailable");
    return api().geterr(p);
}

int datalink(pcap_t* p) {
    if (!resolved()) return -1;
    return api().datalink(p);
}

int next_ex(pcap_t* p, pcap_pkthdr** pkt_header,
            const unsigned char** pkt_data) {
    if (!resolved()) return -1;
    return api().next_ex(p, pkt_header, pkt_data);
}

} // namespace pcapdyn
} // namespace ncp

#endif // _WIN32 && HAVE_PCAP
