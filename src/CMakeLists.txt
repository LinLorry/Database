find_package(OpenSSL REQUIRED)


add_library(Database Security/DatabaseSecurityHeader.cpp until/byte.cpp)

add_executable(test main.cpp)

target_link_libraries(test Database)
target_link_libraries(test ${OPENSSL_LIBRARIES})