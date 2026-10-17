cmake_minimum_required(VERSION 3.20)
project(passkey_host C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(FIDO_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../Apps/Passkey/main/Source/fido")

file(GLOB FIDO_SOURCES
    "${FIDO_DIR}/*.c"
    "${FIDO_DIR}/crypto/*.c"
    "${FIDO_DIR}/crypto/micro-ecc/uECC.c"
    "${FIDO_DIR}/crypto/tiny-aes/aes.c"
)

add_executable(passkey-host
    ${FIDO_SOURCES}
    hal_host.c
    main_host.c
)

target_include_directories(passkey-host PRIVATE "${FIDO_DIR}")
target_compile_definitions(passkey-host PRIVATE
    uECC_SUPPORTS_secp160r1=0
    uECC_SUPPORTS_secp192r1=0
    uECC_SUPPORTS_secp224r1=0
    uECC_SUPPORTS_secp256r1=1
    uECC_SUPPORTS_secp256k1=0
    uECC_OPTIMIZATION_LEVEL=2
)
target_compile_options(passkey-host PRIVATE -Wall -Wextra -Wno-unused-parameter)
if (PASSKEY_SANITIZE)
    target_compile_options(passkey-host PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer -g)
    target_link_options(passkey-host PRIVATE -fsanitize=address,undefined)
endif ()
target_link_libraries(passkey-host PRIVATE pthread)
