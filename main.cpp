#include <numeric>
#include <vector>
#include <iostream>
#include <concepts>
#include <algorithm>
#include <variant>
#include <optional>
#include <cassert>
#include <stack>
#include <map>
#include <cstddef>

// Automaton state API
template<typename T>
concept automaton_state = requires(T v) {
    // We can get the initial state of the automaton
    { T::initial_state() } -> std::convertible_to<T>;
    // We can transition from a step to another by processing a byte
    { static_cast<const T>(v).step(std::byte(0)) } -> std::convertible_to<T>;
    // Is the current state valid?
    { static_cast<const T>(v).is_valid()} -> std::convertible_to<bool>;
    // Can we reach a valid state from the current state?
    { static_cast<const T>(v).is_stuck() } -> std::convertible_to<bool>;
    // There is an order on the states (to be able to use std::map)
    { v <=> v };
};

using bytes = std::vector<std::byte>;
const bytes bytes_empty = {};

// Automaton for fixed-size constants
template<size_t N, size_t M, std::array<std::array<std::byte, M>, N> values>
class InSetAS {
    private:
        bytes cur;
        InSetAS(const bytes& cur) : cur(cur) {}
        InSetAS(bytes&& cur) : cur(std::move(cur)) {}
    public:
        static InSetAS initial_state() {
            return InSetAS(bytes_empty);
        }

        InSetAS step(std::byte c) const {
            bytes new_cur = cur;
            new_cur.push_back(c);
            return InSetAS(std::move(new_cur));
        }

        bool is_stuck() const {
            if(M < cur.size()) {
                return true;
            }

            for(size_t i = 0; i < N; ++i) {
                bool equal = true;
                for(size_t j = 0; j < cur.size(); ++j) {
                    equal = equal && cur[j] == values[i][j];
                }
                if(equal) {
                    return false;
                }
            }
            return true;
        }

        bool is_valid() const {
            return cur.size() == M && !is_stuck();
        }

        auto operator<=>(const InSetAS& x) const = default;
};

// Automaton for fixed-size integers that are between MIN and MAX
template<size_t N, uint64_t MIN, uint64_t MAX>
class InRangeAS {
    private:
        size_t cur_length;
        uint64_t cur_value;
        InRangeAS(size_t cur_length, uint64_t cur_value) : cur_length(cur_length), cur_value(cur_value) {}
    public:
        static InRangeAS initial_state() {
            return InRangeAS(0, 0);
        }

        InRangeAS step(std::byte c) const {
            return InRangeAS(cur_length+1, 256*cur_value+std::to_integer<uint64_t>(c));
        }

        bool is_valid() const {
            return (cur_length == N && MIN <= cur_value && cur_value < MAX);
        }

        bool is_stuck() const {
            if(cur_length < N) {
                uint64_t min_possible_value = cur_value << (8*(N-cur_length));
                uint64_t max_possible_value = (cur_value+1) << (8*(N-cur_length));
                return MAX <= min_possible_value || max_possible_value <= MIN;
            } else if(N == cur_length) {
                return !is_valid();
            } else {
                return true;
            }
        }

        auto operator<=>(const InRangeAS& x) const = default;

        uint64_t get_value() const {
            return cur_value;
        }
};

// Automaton for the concatenation of two automatons
template<automaton_state AS1, automaton_state AS2>
class ConcatenationAS {
    private:
        std::variant<AS1, AS2> state;
        ConcatenationAS(std::variant<AS1, AS2>&& state) : state(std::move(state)) {}
        ConcatenationAS(const std::variant<AS1, AS2>& state) : state(state) {}
    public:
        static ConcatenationAS initial_state() {
            return ConcatenationAS(std::variant<AS1, AS2>(std::in_place_index<0>, AS1::initial_state())).canonicalize();
        }

        ConcatenationAS canonicalize() const {
            if(state.index() == 0 && std::get<0>(state).is_valid()) {
                return ConcatenationAS(std::variant<AS1, AS2>(std::in_place_index<1>, AS2::initial_state()));
            } else {
                return *this;
            }
        }

        ConcatenationAS step(std::byte c) const {
            if(state.index() == 0) {
                return ConcatenationAS(std::variant<AS1, AS2>(std::in_place_index<0>, std::get<0>(state).step(c))).canonicalize();
            } else {
                assert(state.index() == 1);
                return ConcatenationAS(std::variant<AS1, AS2>(std::in_place_index<1>, std::get<1>(state).step(c)));
            }
        }

        bool is_valid() const {
            return state.index() == 1 && std::get<1>(state).is_valid();
        }

        bool is_stuck() const {
            if(state.index() == 0) {
                return std::get<0>(state).is_stuck();
            } else {
                assert(state.index() == 1);
                return std::get<1>(state).is_stuck();
            }
        }

        auto operator<=>(const ConcatenationAS& x) const = default;
};

// Automaton for opaque<MIN..MAX>
template<size_t N, uint64_t MIN, uint64_t MAX>
class OpaqueAS {
    private:
        using SizeAS = InRangeAS<N, MIN, MAX>;
        SizeAS size_as;
        size_t cur_len;
        OpaqueAS(const SizeAS size_as, size_t cur_len) : size_as(size_as), cur_len(cur_len) {}
    public:
        static OpaqueAS initial_state() {
            return OpaqueAS(SizeAS::initial_state(), 0);
        }

        OpaqueAS step(std::byte c) const {
            if(size_as.is_valid()) {
                return OpaqueAS(size_as, cur_len+1);
            } else {
                return OpaqueAS(size_as.step(c), cur_len);
            }
        }

        bool is_valid() const {
            return size_as.is_valid() && cur_len == size_as.get_value();
        }

        bool is_stuck() const {
            return size_as.is_stuck() || (size_as.is_valid() && size_as.get_value() < cur_len);
        }

        auto operator<=>(const OpaqueAS& x) const = default;
};

// Automaton for opaque<N>
template<size_t N>
class FixedLengthOpaqueAS {
    private:
        size_t cur_len;
        FixedLengthOpaqueAS(size_t cur_len) : cur_len(cur_len) {}
    public:
        static FixedLengthOpaqueAS initial_state() {
            return FixedLengthOpaqueAS(0);
        }

        FixedLengthOpaqueAS step(std::byte c) const {
            (void)c;
            return FixedLengthOpaqueAS(cur_len+1);
        }

        bool is_valid() const {
            return cur_len == N;
        }

        bool is_stuck() const {
            return cur_len > N;
        }

        auto operator<=>(const FixedLengthOpaqueAS& x) const = default;
};


//A DFS to find the lexicographically smallest collision
template<automaton_state AS1, automaton_state AS2>
std::optional<bytes> search_collision() {
    using state = std::pair<AS1, AS2>;
    std::stack<state> stack;

    std::map<state, std::pair<state, std::byte>> from;
    state initial_state = std::make_pair(AS1::initial_state(), AS2::initial_state());
    stack.push(initial_state);

    std::optional<state> final_state;

    while(!stack.empty() && !final_state) {
        state cur_st = stack.top(); stack.pop();
        for(int i = 255; i >= 0; --i) {
            std::byte c{uint8_t(i)};
            state next_st = std::make_pair(cur_st.first.step(c), cur_st.second.step(c));
            if(next_st.first.is_valid() && next_st.second.is_valid()) {
                from.insert_or_assign(next_st, std::make_pair(cur_st, c));
                final_state = next_st;
            }
            if(next_st.first.is_stuck() || next_st.second.is_stuck()) {
                continue;
            }
            if(!from.count(next_st)) {
                stack.push(next_st);
            }
            from.insert_or_assign(next_st, std::make_pair(cur_st, c));
        }
    }

    if(final_state) {
        bytes result;
        for(state st = final_state.value(); st != initial_state; st = from.find(st)->second.first) {
            assert(from.count(st));
            result.push_back(from.find(st)->second.second);
        }
        std::ranges::reverse(result);

        return result;
    } else {
        return std::nullopt;
    }
}

constexpr uint8_t hex_digit_to_int(char c) {
    if('0' <= c && c <= '9') {
        return c-'0';
    }
    if('a' <= c && c <= 'f') {
        return 10+c-'a';
    }
    if('A' <= c && c <= 'F') {
        return 10+c-'A';
    }
    assert(false);
}

template<size_t N>
constexpr std::array<std::byte, N> string_to_bytes(std::string_view s) {
    assert(s.size() == 2*N);
    std::array<std::byte, N> result;
    for(size_t i = 0; i < N; ++i) {
        result[i] = std::byte{uint8_t(16*hex_digit_to_int(s[2*i]) + hex_digit_to_int(s[2*i+1]))};
    }
    return result;
}

int main() {
    using CiphersuiteAS = InRangeAS<2, 1, 8>;
    using PublicGroupStateAS =
        ConcatenationAS<InSetAS<1, 1, {{ string_to_bytes<1>("01") }}>, //version
        ConcatenationAS<CiphersuiteAS, //ciphersuite
        ConcatenationAS<OpaqueAS<1, 0, 256>, //group_id
        ConcatenationAS<FixedLengthOpaqueAS<4>, //epoch
        ConcatenationAS<OpaqueAS<1, 32, 256>, //tree_hash
        ConcatenationAS<OpaqueAS<1, 32, 256>, //interim_transcript_hash
        ConcatenationAS<OpaqueAS<4, 0, 256 /* 2^32 */ >, //group_context_extension
        ConcatenationAS<OpaqueAS<4, 0, 256 /* 2^32 */ >, //other_extensions
        ConcatenationAS<OpaqueAS<2, 32, 256 /* 2^16 */ >, //external_pub
                        OpaqueAS<1, 32, 256> //signer
    >>>>>>>>>;

    using CredentialAS =
        ConcatenationAS<InSetAS<1, 2, {{string_to_bytes<2>("0001")}}>, //credential_type
        ConcatenationAS<OpaqueAS<2, 0, 256 /* 2^16 */ >, //identity
        ConcatenationAS<InSetAS<2, 2, {{ string_to_bytes<2>("0807"), string_to_bytes<2>("0403") }}>, //signature_scheme
                        OpaqueAS<2, 32, 256 /* 2^16 */ > //signature_key
    >>>;

    using KeyPackageAS =
        ConcatenationAS<InSetAS<1, 1, {{ string_to_bytes<1>("01") }}>, //version
        ConcatenationAS<CiphersuiteAS, //ciphersuite
        ConcatenationAS<OpaqueAS<2, 32, 256 /* 2^16 */ >, //hpke_init_key
        ConcatenationAS<OpaqueAS<1, 0, 256>, //endpoint_id
        ConcatenationAS<CredentialAS, //credential
                        OpaqueAS<4, 8, 256 /* 2^32 */ > //extensions
    >>>>>;

    using GroupContextAS =
        ConcatenationAS<OpaqueAS<1, 0, 256>, //group_id
        ConcatenationAS<FixedLengthOpaqueAS<4>, //epoch
        ConcatenationAS<OpaqueAS<1, 32, 256>, //tree_hash
        ConcatenationAS<OpaqueAS<1, 32, 256>, //confirmed_transcript_hash
                        OpaqueAS<4, 0, 256> //extensions
    >>>>;

    using MLSPlaintextTBSAS =
        ConcatenationAS<GroupContextAS,
        ConcatenationAS<InSetAS<2, 1, {{ string_to_bytes<1>("01"), string_to_bytes<1>("02") }}>, //wire_format
        ConcatenationAS<OpaqueAS<1, 0, 256>, //group_id
        ConcatenationAS<FixedLengthOpaqueAS<4>, //epoch
        ConcatenationAS<InSetAS<1, 1, {{ string_to_bytes<1>("01") }}>, //sender_type
        ConcatenationAS<FixedLengthOpaqueAS<16>, //member
        ConcatenationAS<OpaqueAS<4, 0, 256 /* 2^32 */ >, //authenticated_data
        ConcatenationAS<InSetAS<1, 1, {{ string_to_bytes<1>("01") }}>, //content_type
                        OpaqueAS<4, 0, 256 /* 2^32 */ > //application_data
    >>>>>>>>;

    //TODO: the "extensions" arrays actually contain garbage data.
    //The collision would be more realistic by coding an automaton state for TLS-serialized arrays

    std::optional<bytes> res = search_collision<MLSPlaintextTBSAS, KeyPackageAS>();
    if(res) {
        printf("Found collision:\n");
        bytes res_bytes = res.value();
        for(size_t i = 0; i < res_bytes.size(); ++i) {
            printf("%02hhx", res_bytes[i]);
        }
        printf("\n");
    } else {
        printf("No collision found\n");
    }

    return 0;
}

