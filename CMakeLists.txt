cmake_minimum_required(VERSION 3.16.3)
project(Cryptoprotocols)

set(CMAKE_CXX_STANDARD 20)

include_directories(lab1)
include_directories(lab2)
include_directories(lab3)
include_directories(lab4)

add_executable(Cryptoprotocols
        lab1/LSX.cpp
        #lab1/LSX.hpp
        #lab2/hmac.hpp
        lab2/hmac.cpp
        lab2/Streebog.cpp
        #lab2/Streebog.hpp
        #lab3/CSPRNG.hpp
        #lab4/CRISP.hpp
        main.cpp
        #auxiliary.hpp
        )
