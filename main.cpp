//
// Created by kadius on 03.08.23.
//

#include "lab4/CRISP.hpp"
#include "lab2/hmac.hpp"

auto
main()
-> int
{

////=======================================================================
//// Diffie-Hellman
////======================================================================
////client side

    BlockVector state{0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x77,0x66,0x55,0x44,0x33,0x22,0x11};

    uint8_t shared_key[32] = {0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10,0x32,0x54,0x76,0x98,0xba, 0xdc, 0xfe, 0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88};
    std::vector<uint8_t> client_cipher_key(32);
    std::vector<uint8_t> client_omac_key(32);

    /////////////////////////////////////////////////////////////////
    ////алгоритм диверсификации ключа
    uint8_t salt[32] = {0x00};
    uint8_t IV[32] = {};
    std::string Pcipher = "диверсифицированный ключ шифрования";
    std::string Pomac = "диверсифицированный ключ для имитовставки";
    std::string U = "username: Kadius Lunarflame";
    hmac::kdf2(shared_key, salt, IV, 0, Pcipher, U, client_cipher_key);
    hmac::kdf2(shared_key, salt, IV, 0, Pomac, U, client_omac_key);

    ///////////////////////////////////////////////////////////////////
    ////Создали сообщение защищенное протоколом CRISP
    const crisp_message msg(std::move(state), std::move(client_cipher_key), std::move(client_omac_key));
    for(size_t i{}; i < 8; ++i) {
        std::cout << std::hex << (int)msg.ICV[i];
    }
    std::cout << std::endl;

//// msg = [header||encrypted data||mac]
////client ====msg====> server (boost.serialization?)
////
//server side

    std::vector<uint8_t> server_cipher_key(32);
    std::vector<uint8_t> server_omac_key(32);
    /////////////////////////////////////////////////////////////////
    ////алгоритм диверсификации ключа
//    данные переменные совпадают и у клиента, и у сервера:
//    uint8_t salt[32] = {0x00};
//    uint8_t IV[32] = {};
//    std::string Pcipher = "диверсифицированный ключ шифрования";
//    std::string Pomac = "диверсифицированный ключ для имитовставки";
//    std::string U = "username: Kadius Lunarflame";
    hmac::kdf2(shared_key, salt, IV, 0, Pcipher, U, server_cipher_key);
    hmac::kdf2(shared_key, salt, IV, 0, Pomac, U, server_omac_key);
    ///////////////////////////////////////////////////////////////////
//// msg <= deserialized

////decrypt message
    LSX cipher(msg.PayloadData, std::move(server_cipher_key));
    cipher.D();
    cipher.show();
////decrypt message
////check MAC
//    BlockVector check(8+16, 0);
    uint8_t check[8+16];
    check[0] = msg.header.version;
    check[1] = msg.header.version >> 8;
    check[2] = msg.header.CS;
    check[3] = msg.header.KeyId;
    check[4] = msg.header.SeqNum;
    check[5] = (msg.header.SeqNum >> 8);
    check[6] = (msg.header.SeqNum >> 16);
    check[7] = (msg.header.SeqNum >> 24);

    for(size_t i{}; i < 16; ++i) {
        check[i+8] = msg.PayloadData[i];
    }

    auto mac = OMAC(crisp_message::MAC_SIZE, check, std::move(server_omac_key));
    for(size_t i{}; i < 8; ++i) {
        std::cout << std::hex << (int)mac[i];
    }
    std::cout << std::endl;
////check MAC

    return 0;
}

