//
// Created by kadius on 24.07.23.
//

#ifndef TESTPROJECT_CSPRNG_HPP
#define TESTPROJECT_CSPRNG_HPP

#include <cstdint>
#include <bitset>
#include <iostream>
#include <iomanip>

class ChaCha20 {
  public:
    ChaCha20() = default;

    ChaCha20(const uint8_t(&key)[32], uint32_t count, const uint8_t(&nonce)[12]) {
        set_constants();
        set_key(key);
        state_[12] = count;
        set_nonce(nonce);
    }

    void encrypt() {
        uint32_t old[16];
        std::copy(state_, state_+16, old);
        for(int i{1}; i <= 10; ++i) {
            inner_block();
        }

        for(int i{}; i < 16; ++i) {
            state_[i] += old[i];
        }
        ++state_[12];
    }

    void show() {
        for(int i{}; i < 4; ++i) {
            for(int j{}; j < 4; ++j) {
                std::cout << std::setfill('0') << std::setw(8)  << std::bitset<32>(state_[4*i+j])/* << " "*/;
            }
//            std::cout << std::endl;
        }
    }

  private:
    void rotl(uint32_t& i, int k) {
        i = ((i << k) | (i >> (32-k)));
    }

    void set_constants() {
        constexpr uint8_t constants[] = "expand 32-byte k";
        auto C = (uint32_t*)constants;
        for(int i{0}; i < 4; ++i) {
            state_[i] = *(C+i);
        }
    }

    void set_key(const uint8_t(&key)[32]) {
        auto* arr = (uint32_t*)key;

        for(int i{4}; i < 12; ++i) {
            state_[i] = *(arr+i-4);
        }
    }

    void set_nonce(const uint8_t(&nonce)[12]) {
        auto* arr = (uint32_t*)nonce;

        for(int i{13}; i < 16; ++i) {
            state_[i] = *(arr+i-13);
        }
    }

    void QUARTERROUND(int a, int b, int c, int d) {
        state_[a] += state_[b]; state_[d] ^= state_[a]; rotl(state_[d], 16);
        state_[c] += state_[d]; state_[b] ^= state_[c]; rotl(state_[b], 12);
        state_[a] += state_[b]; state_[d] ^= state_[a]; rotl(state_[d], 8);
        state_[c] += state_[d]; state_[b] ^= state_[c]; rotl(state_[b], 7);
    }

    void inner_block() {
        QUARTERROUND(0,4,8,12);
        QUARTERROUND(1,5,9,13);
        QUARTERROUND(2,6,10,14);
        QUARTERROUND(3,7,11,15);
        QUARTERROUND(0,5,10,15);
        QUARTERROUND(1,6,11,12);
        QUARTERROUND(2,7,8,13);
        QUARTERROUND(3,4,9,14);
    }

public:
    uint32_t state_[16];
//     0  1  2  3
//     4  5  6  7
//     8  9 10 11
//    12 13 14 15
};

#endif //TESTPROJECT_CSPRNG_HPP