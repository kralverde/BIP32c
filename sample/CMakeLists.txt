cmake_minimum_required(VERSION 3.3)
project(hdwallet_sample)


set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
FIND_PACKAGE(OpenSSL)

include_directories(../include)

set(SOURCE_FILES sample.c)
add_executable(hdwallet_sample ${SOURCE_FILES})
target_link_libraries(hdwallet_sample ${OPENSSL_LIBRARIES} hdwallet)
install(TARGETS hdwallet_sample
        DESTINATION lib)