cmake_minimum_required(VERSION 3.3)
project(hdwallet)


set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
FIND_PACKAGE(OpenSSL)

set(SOURCE_FILES hdwallet.c)
add_library(hdwallet STATIC ${SOURCE_FILES})
target_link_libraries(hdwallet ${OPENSSL_LIBRARIES}
                               base58)
install(TARGETS hdwallet
        DESTINATION lib)