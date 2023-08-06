//
// Created by kadius on 05.04.23.
//
#pragma once

#include <vector>
#include <iostream>

using BlockVector = std::vector<uint8_t>;
using BlockMatrix = std::vector<std::vector<uint8_t>>;

static
auto
operator^(BlockVector& lhs, BlockVector& rhs)
->BlockVector
{
    auto block_sz = lhs.size();
    BlockVector tmp(block_sz, 0);
    for(int i{}; i < block_sz; ++i) {
        tmp[i] = lhs[i]^rhs[i];
    }

    return tmp;
}

static
void
operator^=(BlockVector& lhs, const BlockVector& rhs)
{
    for(int i{}; i < lhs.size(); ++i) {
        lhs[i] ^= rhs[i];
    }
}

static uint8_t gf_mult(uint8_t a, uint8_t b) {
    uint8_t res{};
    while (b != 0) {
        if (b & 1) {
            res ^= a;
        }

        a = (a << 1) ^ (a&0x80?0xc3: 0x00);

        b >>= 1;
    }
    return res;
}

static
void operator<<=(BlockVector& lhs, size_t n) {

    bool msb = lhs[15] & 0x80;
    lhs[0] <<= 1;

    for(int i{1}; i < 16; ++i) {
        bool cur_msb = lhs[i] & 0x80;
        lhs[i] <<= 1;
        lhs[i] |= msb;
        msb = cur_msb;
    }
}


