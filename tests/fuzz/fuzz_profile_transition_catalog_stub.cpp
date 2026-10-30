// Link-only stub for the codec-only fuzz target.
//
// fuzz_profile_transition_codec exercises ProfileTransitionCodec directly and
// never resolves catalog descriptors. The production translation unit also
// contains the transition manager and its catalog resolver; LibFuzzer's
// coverage tables retain those sections, so this single unrelated symbol must
// be provided even though no fuzz input can reach it. Keeping the stub here
// lets the target instrument the real production codec without linking the
// entire (unrelated) ncp_core library.

#include "ncp_reference_profile_catalog.hpp"

namespace ncp {

const ProfileDescriptor* ReferenceProfileCatalog::find(
    const std::string&, uint32_t) const {
    return nullptr;
}

}  // namespace ncp
