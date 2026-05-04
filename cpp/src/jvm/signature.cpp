#include "signature.hpp"
#include <stdexcept>

namespace marrow {

static TosState return_tos(char c) {
    switch (c) {
        case 'V': return TOS_VTOS;
        case 'B': return TOS_BTOS;
        case 'Z': return TOS_ZTOS;
        case 'C': return TOS_CTOS;
        case 'S': return TOS_STOS;
        case 'I': return TOS_ITOS;
        case 'J': return TOS_LTOS;
        case 'F': return TOS_FTOS;
        case 'D': return TOS_DTOS;
        case 'L':
        case '[': return TOS_ATOS;
    }
    throw std::invalid_argument(std::string("unknown return type: ") + c);
}

std::pair<uint32_t, TosState>
parse_descriptor(const std::string& sig, bool is_static)
{
    if (sig.empty() || sig[0] != '(')
        throw std::invalid_argument("bad descriptor: " + sig);
    size_t close = sig.rfind(')');
    if (close == std::string::npos)
        throw std::invalid_argument("no ')' in descriptor: " + sig);
    std::string args = sig.substr(1, close - 1);
    std::string ret  = sig.substr(close + 1);
    if (ret.empty())
        throw std::invalid_argument("no return type in " + sig);

    uint32_t slots = is_static ? 0u : 1u;
    size_t i = 0;
    while (i < args.size()) {
        char c = args[i];
        if (c == 'B' || c == 'Z' || c == 'S' || c == 'C' || c == 'I' || c == 'F') {
            slots += 1; i += 1;
        } else if (c == 'J' || c == 'D') {
            slots += 2; i += 1;
        } else if (c == 'L') {
            slots += 1;
            size_t end = args.find(';', i);
            if (end == std::string::npos)
                throw std::invalid_argument("unterminated L in " + sig);
            i = end + 1;
        } else if (c == '[') {
            slots += 1;
            while (i < args.size() && args[i] == '[') ++i;
            if (i < args.size() && args[i] == 'L') {
                size_t end = args.find(';', i);
                if (end == std::string::npos)
                    throw std::invalid_argument("unterminated L in " + sig);
                i = end + 1;
            } else if (i < args.size()) {
                ++i;
            }
        } else {
            throw std::invalid_argument(
                std::string("unexpected descriptor char '") + c + "' in " + sig);
        }
    }
    return {slots, return_tos(ret[0])};
}

static constexpr uint32_t PARAM_MASK = 0xFF;
static constexpr uint32_t TOS_SHIFT  = 24;
static constexpr uint32_t TOS_MASK   = 0xFu << TOS_SHIFT;

uint32_t synth_flags_legacy(uint32_t donor_flags, const std::string& sig,
                             bool is_static)
{
    auto [slots, tos] = parse_descriptor(sig, is_static);
    uint32_t flags = donor_flags;
    flags = (flags & ~PARAM_MASK) | (slots & PARAM_MASK);
    flags = (flags & ~TOS_MASK)   | ((uint32_t(tos) & 0xF) << TOS_SHIFT);
    return flags;
}

} // namespace marrow
