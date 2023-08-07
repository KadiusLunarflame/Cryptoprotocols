//
// Created by kadius on 04.04.23.
//

#ifndef TESTPROJECT_LSX_HPP
#define TESTPROJECT_LSX_HPP

#include <iomanip>
#include <vector>
#include <iostream>
#include <iterator>
#include <fstream>

#include "../auxiliary.hpp"

//#include "crc.hpp"

namespace cipher {

class LSX {

private:
    void time_stamp() {
        time_t result = time(NULL);
        if(result != (time_t)(-1))
            log << asctime(gmtime(&result));
    }

    std::ofstream log;

    static constexpr size_t state_size_{16};
    uint8_t poly{0xc3};

    BlockVector sbox_ = {0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB,
                         0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D, 0xE9, 0x77,
                         0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1,
                         0xBB, 0x14, 0xCD, 0x5F, 0xC1, 0xF9, 0x18, 0x65, 0x5A,
                         0xE2, 0x5C, 0xEF, 0x21, 0x81, 0x1C, 0x3C, 0x42, 0x8B,
                         0x01, 0x8E, 0x4F, 0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A,
                         0x8F, 0xA0, 0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3,
                         0x1F, 0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB,
                         0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC, 0xB5,
                         0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12, 0xBF, 0x72,
                         0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87, 0x15, 0xA1, 0x96,
                         0x29, 0x10, 0x7B, 0x9A, 0xC7, 0xF3, 0x91, 0x78, 0x6F,
                         0x9D, 0x9E, 0xB2, 0xB1, 0x32, 0x75, 0x19, 0x3D, 0xFF,
                         0x35, 0x8A, 0x7E, 0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD,
                         0x0D, 0x57, 0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43,
                         0xC9, 0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
                         0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC, 0xDC,
                         0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A, 0xA7, 0x97,
                         0x60, 0x73, 0x1E, 0x00, 0x62, 0x44, 0x1A, 0xB8, 0x38,
                         0x82, 0x64, 0x9F, 0x26, 0x41, 0xAD, 0x45, 0x46, 0x92,
                         0x27, 0x5E, 0x55, 0x2F, 0x8C, 0xA3, 0xA5, 0x7D, 0x69,
                         0xD5, 0x95, 0x3B, 0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC,
                         0x1D, 0xF7, 0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7,
                         0x89, 0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE,
                         0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61, 0x20,
                         0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B, 0xCB, 0x9B,
                         0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52, 0x59, 0xA6, 0x74,
                         0xD2, 0xE6, 0xF4, 0xB4, 0xC0, 0xD1, 0x66, 0xAF, 0xC2,
                         0x39, 0x4B, 0x63, 0xB6};

    BlockVector sbox_inv_ = {
            0xA5, 0x2D, 0x32, 0x8F, 0x0E, 0x30, 0x38, 0xC0,
            0x54, 0xE6, 0x9E, 0x39, 0x55, 0x7E, 0x52, 0x91,
            0x64, 0x03, 0x57, 0x5A, 0x1C, 0x60, 0x07, 0x18,
            0x21, 0x72, 0xA8, 0xD1, 0x29, 0xC6, 0xA4, 0x3F,
            0xE0, 0x27, 0x8D, 0x0C, 0x82, 0xEA, 0xAE, 0xB4,
            0x9A, 0x63, 0x49, 0xE5, 0x42, 0xE4, 0x15, 0xB7,
            0xC8, 0x06, 0x70, 0x9D, 0x41, 0x75, 0x19, 0xC9,
            0xAA, 0xFC, 0x4D, 0xBF, 0x2A, 0x73, 0x84, 0xD5,
            0xC3, 0xAF, 0x2B, 0x86, 0xA7, 0xB1, 0xB2, 0x5B,
            0x46, 0xD3, 0x9F, 0xFD, 0xD4, 0x0F, 0x9C, 0x2F,
            0x9B, 0x43, 0xEF, 0xD9, 0x79, 0xB6, 0x53, 0x7F,
            0xC1, 0xF0, 0x23, 0xE7, 0x25, 0x5E, 0xB5, 0x1E,
            0xA2, 0xDF, 0xA6, 0xFE, 0xAC, 0x22, 0xF9, 0xE2,
            0x4A, 0xBC, 0x35, 0xCA, 0xEE, 0x78, 0x05, 0x6B,
            0x51, 0xE1, 0x59, 0xA3, 0xF2, 0x71, 0x56, 0x11,
            0x6A, 0x89, 0x94, 0x65, 0x8C, 0xBB, 0x77, 0x3C,
            0x7B, 0x28, 0xAB, 0xD2, 0x31, 0xDE, 0xC4, 0x5F,
            0xCC, 0xCF, 0x76, 0x2C, 0xB8, 0xD8, 0x2E, 0x36,
            0xDB, 0x69, 0xB3, 0x14, 0x95, 0xBE, 0x62, 0xA1,
            0x3B, 0x16, 0x66, 0xE9, 0x5C, 0x6C, 0x6D, 0xAD,
            0x37, 0x61, 0x4B, 0xB9, 0xE3, 0xBA, 0xF1, 0xA0,
            0x85, 0x83, 0xDA, 0x47, 0xC5, 0xB0, 0x33, 0xFA,
            0x96, 0x6F, 0x6E, 0xC2, 0xF6, 0x50, 0xFF, 0x5D,
            0xA9, 0x8E, 0x17, 0x1B, 0x97, 0x7D, 0xEC, 0x58,
            0xF7, 0x1F, 0xFB, 0x7C, 0x09, 0x0D, 0x7A, 0x67,
            0x45, 0x87, 0xDC, 0xE8, 0x4F, 0x1D, 0x4E, 0x04,
            0xEB, 0xF8, 0xF3, 0x3E, 0x3D, 0xBD, 0x8A, 0x88,
            0xDD, 0xCD, 0x0B, 0x13, 0x98, 0x02, 0x93, 0x80,
            0x90, 0xD0, 0x24, 0x34, 0xCB, 0xED, 0xF4, 0xCE,
            0x99, 0x10, 0x44, 0x40, 0x92, 0x3A, 0x01, 0x26,
            0x12, 0x1A, 0x48, 0x68, 0xF5, 0x81, 0x8B, 0xC7,
            0xD6, 0x20, 0x0A, 0x08, 0x00, 0x4C, 0xD7, 0x74
    };

    BlockVector lvec_ = {0x01, 0x94, 0x20, 0x85, 0x10, 0xc2, 0xc0, 0x01, 0xfb, 0x01, 0xc0, 0xc2, 0x10, 0x85, 0x20, 0x94};

    BlockMatrix round_constants_;
    BlockVector state_;//the block to which the LSX transformations are gonna be applied to.
    BlockVector master_key_;
    BlockMatrix keys_;//key schedule

public:

    template<typename Vector>
    LSX(Vector&& master_key) {
        log = std::ofstream("lsxlog.txt", std::ios_base::app);

        initialize_round_constants();
        master_key_ = BlockVector{0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01,0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88};
        state_ = BlockVector{0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x77,0x66,0x55,0x44,0x33,0x22,0x11};
        key_schedule();
        E();
        BlockVector test_case = {0x7f,0x67,0x9d,0x90,0xbe,0xbc,0x24,0x30,0x5a,0x46,0x8d,0x42,0xb9,0xd4,0xed,0xcd};
        for(size_t i{}; i < 16; ++i) {
            //TEST CASE FAIL:
            if(state_[i] != test_case[15-i]) {
                std::cout << "PROGRAM HAS BEEN COMPROMISED!";
                time_stamp();
                log << ("...from cipher class constructor->") << this;
                log << "PROGRAM HAS BEEN COMPROMISED!" << std::endl;
            }
        }

        state_.clear();
        keys_.clear();
        master_key_ = std::forward<Vector>(master_key);
        key_schedule();
    }

    template<typename Vector>
    LSX(BlockVector&& state, Vector&& master_key) {
        log = std::ofstream("lsxlog.txt", std::ios_base::app);

        initialize_round_constants();
        master_key_ = BlockVector{0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01,0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88};
        state_ = BlockVector{0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x77,0x66,0x55,0x44,0x33,0x22,0x11};
        key_schedule();
        E();
        BlockVector test_case = {0x7f,0x67,0x9d,0x90,0xbe,0xbc,0x24,0x30,0x5a,0x46,0x8d,0x42,0xb9,0xd4,0xed,0xcd};
        for(size_t i{}; i < 16; ++i) {
            //TEST CASE FAIL:
            if(state_[i] != test_case[15-i]) {
                std::cout << "PROGRAM HAS BEEN COMPROMISED!";
                time_stamp();
                log << ("...from cipher class constructor->") << this;
                log << "PROGRAM HAS BEEN COMPROMISED!" << std::endl;
            }
        }

        state_.clear();
        keys_.clear();
        master_key_ = std::forward<Vector>(master_key);
        key_schedule();
        state_ = std::move(state);
    }

    template<typename State, typename Vector>
    LSX(State& state, Vector&& master_key) {
        log = std::ofstream("lsxlog.txt", std::ios_base::app);

        initialize_round_constants();
        master_key_ = BlockVector{0xef,0xcd,0xab,0x89,0x67,0x45,0x23,0x01,0x10,0x32,0x54,0x76,0x98,0xba,0xdc,0xfe,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88};
        state_ = BlockVector{0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x77,0x66,0x55,0x44,0x33,0x22,0x11};
        key_schedule();
        E();
        BlockVector test_case = {0x7f,0x67,0x9d,0x90,0xbe,0xbc,0x24,0x30,0x5a,0x46,0x8d,0x42,0xb9,0xd4,0xed,0xcd};
        for(size_t i{}; i < 16; ++i) {
            //TEST CASE FAIL:
            if(state_[i] != test_case[15-i]) {
                std::cout << "PROGRAM HAS BEEN COMPROMISED!";
                time_stamp();
                log << ("...from cipher class constructor->") << this;
                log << "PROGRAM HAS BEEN COMPROMISED!" << std::endl;
            }
        }

        state_.clear();
        keys_.clear();
        master_key_ = std::forward<Vector>(master_key);
        key_schedule();
        state_.resize(state_size_);
        for(size_t i{}; i < state_size_; ++i) {
            state_.at(i) = state[i];
        }
    }

    ~LSX() {
        //fill in key information with zeroes so that it would not remain in memory
        for(auto& k: master_key_) {
            k &= 0x00;
        }

        for(auto& k: master_key_) {
            if (k != 0x00) {
                std::cout << "THE KEY HAS BEEN COMPROMISED!" << std::endl;
                time_stamp();
                log << ("...from cipher class destructor->") << this;
                log << "THE KEY HAS BEEN COMPROMISED!" << std::endl;
            }
        }
    }
private:
    void initialize_round_constants() {
        for(uint8_t i{1}; i <= 32; ++i) {
            BlockVector tmp(16, 0);
            tmp[0] = i;

            L(tmp);

            round_constants_.emplace_back(std::move(tmp));
        }
    }

    LSX& X(const BlockVector& key);
    void X(BlockVector& state, const BlockVector& key);

    LSX& R();
    LSX& R(BlockVector& state);

    LSX& S();
    void S(BlockVector& state);


    LSX& L();
    LSX& L(BlockVector& state);

    LSX& R_inv();
    LSX& R_inv(BlockVector& state);

    LSX& S_inv();
    void S_inv(BlockVector& state);

    LSX& L_inv();
    LSX& L_inv(BlockVector& state);

    BlockVector
    F(const BlockVector& Ki, const BlockVector& C);

    void
    key_schedule();
public:
    void E();
    void E(BlockVector&& msg);

    void D();
    void D(BlockVector&& msg);
private:
    friend
    BlockVector
    OMAC(size_t s, const BlockVector& message, BlockVector&& key);

    BlockVector
    OMAC_impl(size_t s, const BlockVector& message) {
        std::vector<uint8_t> B(16, 0);
        B[0] = 0x87;
        std::vector<uint8_t> state(16,0);

        E(std::move(state));
        auto R = get_state();

        BlockVector K1, K2;
        if(R.back() & 0x80) {
            R <<= 1;
            K1 = std::move(R);
            K1 ^= B;
        } else {
            R <<= 1;
            K1 = std::move(R);
        }

        auto tmpK1 = K1;

        if(K1.back() & 0x80) {
            tmpK1 <<= 1;
            K2 = std::move(tmpK1);
            K2 ^= B;
        } else {
            tmpK1 <<= 1;
            K2 = std::move(tmpK1);
        }

        std::vector<uint8_t> C0(16, 0);
        set_state(std::move(C0));

        size_t num = message.size()/16;
        size_t incomplete = message.size()%16;

        std::vector<std::vector<uint8_t>> messages(num, std::vector<uint8_t>(16, 0));

        for(size_t i{}; i < num; ++i) {
            for(size_t j{}; j < 16; ++j) {
                messages[i][j] = message[i*16+j];
            }
        }

        if(incomplete == 0) {

            for(size_t i{}; i < num-1; ++i) {
                X(messages[i]).E();
            }

            X(messages[num-1]).X(K1).E();
            auto res = get_state();
//            res.resize(s/8);
            std::vector<uint8_t> result;
            auto iterator = res.end();
            std::advance(iterator, -(s/8));
            for(;iterator != res.end(); ++iterator) {
                result.push_back(*iterator);
            }

            return result;
        }

        std::vector<uint8_t> last_msg{16, 0};
        size_t last_message_begin_index = message.size()-incomplete;
        size_t last_message_length = incomplete;
        size_t j{};
        for (; j < last_message_length; ++j) {
            last_msg[j] = message[last_message_begin_index + j];
        }
        last_msg[incomplete] = 1;

        X(last_msg).X(K2).E();
        auto res = get_state();

        std::vector<uint8_t> result;
        auto iterator = res.end();
        std::advance(iterator, -(s/8));
        for(;iterator != res.end(); ++iterator) {
            result.push_back(*iterator);
        }

        return result;
    }

    template<size_t N>
    friend BlockVector OMAC(size_t s, const uint8_t (&message)[N], BlockVector&& key);

    template<size_t msg_length>
    BlockVector
    OMAC_impl(size_t s, const uint8_t (&message)[msg_length]) {
        std::vector<uint8_t> B(16, 0);
        B[0] = 0x87;
        std::vector<uint8_t> state(16,0);

        E(std::move(state));
        auto R = get_state();

        BlockVector K1, K2;
        if(R.back() & 0x80) {
            R <<= 1;
            K1 = std::move(R);
            K1 ^= B;
        } else {
            R <<= 1;
            K1 = std::move(R);
        }

        auto tmpK1 = K1;

        if(K1.back() & 0x80) {
            tmpK1 <<= 1;
            K2 = std::move(tmpK1);
            K2 ^= B;
        } else {
            tmpK1 <<= 1;
            K2 = std::move(tmpK1);
        }

        std::vector<uint8_t> C0(16, 0);
        set_state(std::move(C0));

        size_t num = msg_length/16;
        size_t incomplete = msg_length%16;

        std::vector<std::vector<uint8_t>> messages(num, std::vector<uint8_t>(16, 0));

        for(size_t i{}; i < num; ++i) {
            for(size_t j{}; j < 16; ++j) {
                messages[i][j] = message[i*16+j];
            }
        }

        if(incomplete == 0) {

            for(size_t i{}; i < num-1; ++i) {
                X(messages[i]).E();
            }

            X(messages[num-1]).X(K1).E();
            auto res = get_state();
//            res.resize(s/8);
            std::vector<uint8_t> result;
            auto iterator = res.end();
            std::advance(iterator, -(s/8));
            for(;iterator != res.end(); ++iterator) {
                result.push_back(*iterator);
            }

            return result;
        }

        std::vector<uint8_t> last_msg{16, 0};
        size_t last_message_begin_index = msg_length-incomplete;
        size_t last_message_length = incomplete;
        size_t j{};
        for (; j < last_message_length; ++j) {
            last_msg[j] = message[last_message_begin_index + j];
        }
        last_msg[incomplete] = 1;

        X(last_msg).X(K2).E();
        auto res = get_state();

        std::vector<uint8_t> result;
        auto iterator = res.end();
        std::advance(iterator, -(s/8));
        for(;iterator != res.end(); ++iterator) {
            result.push_back(*iterator);
        }

        return result;
    }

public:
    auto show() {
        for(auto it = state_.rbegin(); it != state_.rend(); ++it) {
            std::cout << std::hex << std::setfill('0') << std::setw(2) << (int)(*it);
        }
        std::cout << std::endl;
    }

    void
    set_state(BlockVector&& state) {
        state_ = std::move(state);
    }

    BlockVector
    get_state() {
        return state_;
    }

    void load_state(uint8_t (&dest)[state_size_]) {
        for(size_t i{}; i < state_size_; ++i) {
            dest[i] = state_.at(i);
        }
    }
};

    BlockVector
    OMAC(size_t s, const BlockVector& message,/* size_t msg_length,*/ BlockVector&& key);

    template<size_t N>
    BlockVector OMAC(size_t s, const uint8_t (&message)[N], BlockVector&& key);
}//cipher
#endif