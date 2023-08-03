//
// Created by kadius on 03.08.23.
//

#ifndef TESTPROJECT_CRISP_HPP
#define TESTPROJECT_CRISP_HPP

#include <cstdint>
#include <iostream>
#include <array>

#include "LSX.hpp"

using namespace cipher;

struct crisp_message {

    static constexpr size_t CRISP_SIZE = 1024;
    static constexpr size_t MAC_SIZE = 64;

    struct crisp_header{
        uint16_t version = 0x0000;// = ExternalKeyIdFlag & Version
        uint8_t CS = 0xF9;
        uint8_t KeyId = 0x80;
        uint64_t SeqNum = 0;//порядковый номер сообщения. длина равна длине синхропосылки
    };
    crisp_header header;//12 bytes
    std::vector<uint8_t> PayloadData;//128 bytes
    std::vector<uint8_t> ICV;//имитовставка всего сообщения

    //TODO:: arbitrary msg length
    //TODO:: rework move_semantics interface of keys
    //for now message length = one block
    crisp_message(BlockVector&& message, const BlockVector& cipher_key, BlockVector&& omac_key) {
        LSX cipher{cipher_key};
        cipher.E(std::move(message));
        PayloadData = cipher.get_state();

        BlockVector this_message(12+128, 0);
        this_message[2] = header.CS;
        this_message[3] = header.KeyId;
        this_message[4] = header.SeqNum;
        this_message[5] = (header.SeqNum >> 8);
        this_message[6] = (header.SeqNum >> 16);
        this_message[7] = (header.SeqNum >> 24);
        this_message[8] = (header.SeqNum >> 32);
        this_message[9] = (header.SeqNum >> 40);
        this_message[10] = (header.SeqNum >> 48);
        this_message[11] = (header.SeqNum >> 56);

        for(size_t i{}; i < 128; ++i) {
            this_message[i+12] = PayloadData[i];
        }

        OMAC(MAC_SIZE, this_message, 12+128, std::move(omac_key), ICV);
    }


};


#endif //TESTPROJECT_CRISP_HPP