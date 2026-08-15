// ncp_wfp_guids.cpp — definitions of WFP built-in layer/condition GUIDs.
// mingw-w64's libfwpuclnt.a exports no GUID data symbols and its fwpmu.h does
// not even declare them, so we define the ones ncp_core uses here.
// Values verified against Windows 10 SDK fwpmu.h/fwpmk.h (10.0.10240 and
// 10.0.26100), OpenVPN block_dns.c and wireguard-windows types_windows.go.
// NOTE: `extern` is required on each definition — a namespace-scope const
// without it has internal linkage in C++ and would be dead-stripped at -O3.
#if defined(_WIN32)
#include <winsock2.h>
#include <windows.h>
#include <guiddef.h>

extern "C" {

extern const GUID FWPM_LAYER_ALE_AUTH_CONNECT_V4 =
    {0xc38d57d1, 0x05a7, 0x4c33, {0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}};
extern const GUID FWPM_LAYER_ALE_AUTH_CONNECT_V6 =
    {0x4a72393b, 0x319f, 0x44bc, {0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}};
extern const GUID FWPM_LAYER_OUTBOUND_TRANSPORT_V4 =
    {0x09e61aea, 0xd214, 0x46e2, {0x9b, 0x21, 0xb2, 0x6b, 0x0b, 0x2f, 0x28, 0xc8}};
extern const GUID FWPM_CONDITION_IP_PROTOCOL =
    {0x3971ef2b, 0x623e, 0x4f9a, {0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7}};
extern const GUID FWPM_CONDITION_IP_REMOTE_ADDRESS =
    {0xb235ae9a, 0x1d64, 0x49b8, {0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45}};
extern const GUID FWPM_CONDITION_IP_REMOTE_PORT =
    {0xc35a604d, 0xd22b, 0x4e1a, {0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b}};

} // extern "C"
#endif // _WIN32
