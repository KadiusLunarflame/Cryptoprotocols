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

    static constexpr size_t CRISP_SIZE = 32;
    static constexpr size_t MAC_SIZE = 64;

    struct crisp_header{
        uint16_t version = 0x0000;// = ExternalKeyIdFlag & Version
        uint8_t CS = 0xF9;
        uint8_t KeyId = 0x80;
        uint32_t SeqNum = 0;//порядковый номер сообщения. длина равна длине синхропосылки
    };
    crisp_header header;//16 bytes
    uint8_t PayloadData[16];//16 bytes
    uint8_t ICV[8];//имитовставка всего сообщения

    //TODO:: arbitrary msg length
    //TODO:: rework move_semantics interface of keys
    //for now message length = one block
    crisp_message(BlockVector&& message, BlockVector&& cipher_key, BlockVector&& omac_key) {
        LSX cipher(std::move(cipher_key));
        cipher.E(std::move(message));
        cipher.load_state(PayloadData);

        BlockVector this_message(8+16, 0);
        this_message[0] = header.version;
        this_message[1] = header.version >> 8;
        this_message[2] = header.CS;
        this_message[3] = header.KeyId;
        this_message[4] = header.SeqNum;
        this_message[5] = (header.SeqNum >> 8);
        this_message[6] = (header.SeqNum >> 16);
        this_message[7] = (header.SeqNum >> 24);

        for(size_t i{}; i < 16; ++i) {
            this_message[i+8] = PayloadData[i];
        }

        auto mac = OMAC(MAC_SIZE, this_message,std::move(omac_key));
        std::copy(mac.begin(), mac.end(), ICV);
    }
};


#endif //TESTPROJECT_CRISP_HPP
