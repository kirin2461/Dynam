#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// Soft (runtime) loading of wpcap.dll on Windows.
//
// Historically ncp.exe linked against wpcap.lib, which put wpcap.dll into the
// PE import table: the binary refused to START on systems without WinPcap or
// without Npcap's "WinPcap API-compatible mode". Now wpcap.dll is resolved
// with LoadLibrary on first use — a plain Npcap install (System32\Npcap)
// works out of the box, and systems with no pcap at all simply get
// "feature unavailable" instead of a process boot failure.
// ─────────────────────────────────────────────────────────────────────────────
#if defined(_WIN32) && defined(HAVE_PCAP)

#include <pcap.h>  // Npcap SDK headers: types only, no import library needed

namespace ncp {
namespace pcapdyn {

// True when wpcap.dll (WinPcap, or Npcap in native or API-compatible mode)
// was found and all entry points resolved. The first call performs the load;
// the result is cached (thread-safe).
bool available();

// Drop-in replacements for the libpcap entry points used by NCP.
// Without wpcap.dll they return libpcap-style error codes (-1 / nullptr)
// and fill errbuf where the real API would.
int     findalldevs(pcap_if_t** alldevs, char* errbuf);
void    freealldevs(pcap_if_t* alldevs);
pcap_t* open_live(const char* device, int snaplen, int promisc, int to_ms,
                  char* errbuf);
void    close(pcap_t* p);
int     sendpacket(pcap_t* p, const unsigned char* buf, int size);
char*   geterr(pcap_t* p);
int     datalink(pcap_t* p);
int     next_ex(pcap_t* p, pcap_pkthdr** pkt_header,
                const unsigned char** pkt_data);

} // namespace pcapdyn
} // namespace ncp

// Route call sites through the dynamic loader (the .cpp defines
// NCP_PCAP_DYN_IMPL to see the real prototypes instead).
#ifndef NCP_PCAP_DYN_IMPL
#define pcap_findalldevs ::ncp::pcapdyn::findalldevs
#define pcap_freealldevs ::ncp::pcapdyn::freealldevs
#define pcap_open_live   ::ncp::pcapdyn::open_live
#define pcap_close       ::ncp::pcapdyn::close
#define pcap_sendpacket  ::ncp::pcapdyn::sendpacket
#define pcap_geterr      ::ncp::pcapdyn::geterr
#define pcap_datalink    ::ncp::pcapdyn::datalink
#define pcap_next_ex     ::ncp::pcapdyn::next_ex
#endif

#endif // _WIN32 && HAVE_PCAP
