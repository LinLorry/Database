find_package(OpenSSL REQUIRED)

add_executable(test main.cpp Security/DatabaseSecurityHeader.cpp)
target_link_libraries(test ${OPENSSL_LIBRARIES})