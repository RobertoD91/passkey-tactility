include("$ENV{TACTILITY_SDK_PATH}/TactilitySDK.cmake")

file(GLOB SOURCE_FILES
    Source/*.c
    Source/fido/*.c
    Source/fido/crypto/*.c
    Source/fido/crypto/micro-ecc/uECC.c
    Source/fido/crypto/tiny-aes/aes.c
)
# sdk-overlay/ holds the usb_hid_device.h of the Tactility FIDO patch (see ../../tactility-patch/), so
# the app builds against a stock SDK that doesn't have the new declarations yet. It comes before
# the SDK's own include path.
tactility_component_register(SRCS ${SOURCE_FILES} INCLUDE_DIRS sdk-overlay Source Source/fido)

# Only P-256 is needed; the other micro-ecc curves would waste flash.
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    uECC_SUPPORTS_secp160r1=0
    uECC_SUPPORTS_secp192r1=0
    uECC_SUPPORTS_secp224r1=0
    uECC_SUPPORTS_secp256r1=1
    uECC_SUPPORTS_secp256k1=0
    uECC_OPTIMIZATION_LEVEL=2
)
set_source_files_properties(Source/fido/crypto/micro-ecc/uECC.c PROPERTIES COMPILE_OPTIONS "-Wno-unused-function;-Wno-sign-compare;-Wno-unused-parameter")
