cmake_minimum_required(VERSION 3.14)

project(Database)

if (OPENSSL_FOUND)
    include_directories(${OPENSSL_INCLUDE_DIR})
    link_libraries(${OPENSSL_LIBRARIES})
endif (OPENSSL_FOUND)

include_directories(include)

add_subdirectory(src)