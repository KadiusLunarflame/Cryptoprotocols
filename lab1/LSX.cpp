//
// Created by kadius on 04.04.23.
//

#include "LSX.hpp"

namespace cipher {

LSX& LSX::X(const BlockVector& key) {
    for(size_t i = 0; i < state_size_; ++i) {
        state_[i] ^= key[i];
    }
    return *this;
}

void LSX::X(BlockVector& state, const BlockVector& key) {
    for(size_t i{}; i < state_size_; ++i) {
        state[i] ^= key[i];
    }
}

LSX& LSX::S() {
    for (size_t i{}; i < state_size_; ++i) {
        state_[i] = sbox_[state_[i]];
    }

    return *this;
}

void LSX::S(BlockVector& state) {
    for (size_t i{}; i < state_size_; ++i) {
        state[i] = sbox_[state[i]];
    }
}

LSX& LSX::S_inv() {
    for (size_t i{}; i < state_size_; ++i) {
        state_[i] = sbox_inv_[state_[i]];
    }

    return *this;
}

void LSX::S_inv(BlockVector& state) {
    for (size_t i{}; i < state_size_; ++i) {
        state[i] = sbox_inv_[state[i]];
    }
}

LSX& LSX::R() {
    uint8_t l{state_[0]};

    for(size_t i{1}; i < state_size_; ++i) {
        l ^= gf_mult(lvec_[i], state_[i]);
        state_[i-1] = state_[i];
    }
    state_[15] = l;
    return *this;
}

LSX& LSX::R(BlockVector& state) {
    uint8_t l{state[0]};

    for(size_t i{1}; i < state_size_; ++i) {
        l ^= gf_mult(lvec_[i], state[i]);
        state[i-1] = state[i];
    }

    state[15] = l;

    return *this;
}

LSX& LSX::R_inv() {
    uint8_t l{state_[15]};

    for(int i{14}; i >= 0; --i) {
        l ^= gf_mult(lvec_[i+1], state_[i]);
        state_[i+1] = state_[i];
    }
    state_[0] = l;
    return *this;
}

LSX& LSX::R_inv(BlockVector& state) {
    uint8_t l{state[15]};

    for(int i{14}; i >= 0; --i) {
        l ^= gf_mult(lvec_[i+1], state[i]);
        state_[i+1] = state[i];
    }

    state[0] = l;
    return *this;
}

LSX& LSX::L() {

    for(size_t i{}; i < state_size_; ++i) {
        R();
    }

    return *this;
}

LSX& LSX::L(BlockVector& state) {

    for(size_t i{}; i < state_size_; ++i) {
        R(state);
    }

    return *this;
}

LSX& LSX::L_inv() {

    for(size_t i{}; i < state_size_; ++i) {
        R_inv();
    }

    return *this;
}

LSX& LSX::L_inv(BlockVector& state) {

    for(size_t i{}; i < state_size_; ++i) {
        R_inv(state);
    }

    return *this;
}

//Feistel function
auto
LSX::F(const BlockVector& Ki, const BlockVector& C)
-> BlockVector
{
    auto internal = Ki;

    X(internal, C);
    S(internal);
    L(internal);

    return internal;
}

//Feistel net
auto
LSX::key_schedule()//16-byte master key
-> void
{
    BlockVector K1;
    BlockVector K2;

    size_t i{};
    for(; i < 16; ++i)
        K2.push_back(master_key_[i]);

    for(; i < 32; ++i)
        K1.push_back(master_key_[i]);

    keys_.emplace_back(std::move(K1));
    keys_.emplace_back(std::move(K2));

    auto r = keys_[0];
    auto l = keys_[1];
    for(i = 0; i < 4; ++i) {
        for (size_t j{}; j < 8; ++j) {
            auto old_r = r;
            auto internal = F(r, round_constants_[8*i+j]);
            r = l ^ internal;
            l = old_r;
        }
        keys_.emplace_back(r);
        keys_.emplace_back(l);
    }
}

void
LSX::E() {
    for(size_t round{}; round < 9; ++round)
        X(keys_[round]).S().L();

    X(keys_[9]);
}

void
LSX::E(BlockVector&& msg) {
    state_ = std::move(msg);

    for(size_t round{}; round < 9; ++round)
        X(keys_[round]).S().L();

    X(keys_[9]);
}

void
LSX::D() {
    for(size_t round{9}; round; --round)
        X(keys_[round]).L_inv().S_inv();

    X(keys_[0]);
}

void
LSX::D(BlockVector&& msg) {
    state_ = std::move(msg);

    for(size_t round{9}; round; --round)
        X(keys_[round]).L_inv().S_inv();

    X(keys_[0]);
}

BlockVector
OMAC(size_t s, const BlockVector& message, BlockVector&& key)
{
    auto log = std::ofstream("omaclog.txt", std::ios_base::app);

    //TEST CASE
    BlockVector test_case = {0xe3,0xfb,0x59,0x60,0x29,0x4d,0x6f,0x33};
    BlockVector test_message{0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x11, 0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22};

    BlockVector test_key{0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88};

    LSX test_cipher(std::move(test_key));
    auto res = test_cipher.OMAC_impl(64, test_message/*, 16*4*/);
    if(res != test_case) {
        std::cout << "OMAC IMPLEMENTATION HAS BEEN COMPROMISED!" << std::endl;
        std::cout << "...aborting now." << std::endl;

        time_t result = time(NULL);
        if(result != (time_t)(-1))
            log << asctime(gmtime(&result));
        log << "[OMAC IMPLEMENTATION HAS BEEN COMPROMISED!]" << std::endl;
        log << "[...aborting now.]" << std::endl;

        exit(3);
    }

    LSX cipher(std::move(key));
    return cipher.OMAC_impl(s, message/*, msg_length*/);
}
template<size_t N>
BlockVector
OMAC(size_t s, const uint8_t (&message)[N], BlockVector&& key) {
//    auto log = std::ofstream("omaclog.txt", std::ios_base::app);
//
//    //TEST CASE
//    BlockVector test_case = {0xe3,0xfb,0x59,0x60,0x29,0x4d,0x6f,0x33};
//    BlockVector test_message{0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x11, 0x00, 0x0a, 0xff, 0xee, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22};
//
//    BlockVector test_key{0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88};
//
//    LSX test_cipher(std::move(test_key));
//    auto res = test_cipher.OMAC_impl(64, test_message, 16*4);
//    if(res != test_case) {
//        std::cout << "OMAC IMPLEMENTATION HAS BEEN COMPROMISED!" << std::endl;
//        std::cout << "...aborting now." << std::endl;
//
//        time_t result = time(NULL);
//        if(result != (time_t)(-1))
//        log << asctime(gmtime(&result));
//        log << "[OMAC IMPLEMENTATION HAS BEEN COMPROMISED!]" << std::endl;
//        log << "[...aborting now.]" << std::endl;
//
//        exit(3);
//    }

    LSX cipher(std::move(key));
    return cipher.OMAC_impl(s, message);
}

}