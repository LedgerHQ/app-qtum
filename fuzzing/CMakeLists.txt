cmake_minimum_required(VERSION 3.10)

project(QtumFuzzer VERSION 0.1 LANGUAGES C)

set(CMAKE_C_STANDARD 11)

# BOLOS SDK
set(BOLOS_SDK $ENV{BOLOS_SDK})
add_compile_definitions(IO_HID_EP_LENGTH=64)

add_compile_definitions(HAVE_ECC HAVE_HASH HAVE_SHA256 HAVE_RIPEMD160)
include_directories(.
        ../src
        "${BOLOS_SDK}/include"
        "${BOLOS_SDK}/lib_cxng/include"
        "${BOLOS_SDK}/lib_cxng/src"
        "${BOLOS_SDK}"
        "${APP_SRC_DIR}/handler/lib/"
)

add_compile_options(-g -ggdb2 -O3 -funsigned-char)

# Build with code coverage generation
if(CODE_COVERAGE)
    if(CMAKE_C_COMPILER_ID MATCHES "(Apple)?[Cc]lang")
        add_compile_options(-fprofile-instr-generate -fcoverage-mapping)
        add_link_options(-fprofile-instr-generate -fcoverage-mapping)
    elseif(CMAKE_C_COMPILER_ID MATCHES "GNU")
        add_compile_options(-fprofile-arcs -ftest-coverage)
        link_libraries(gcov)
    else()
        message(FATAL_ERROR "Unsupported compiler used with code coverage generation")
    endif()
endif()

# Fuzzer target
set(APP_SRC_DIR "../src")

add_definitions(
    -DAPPNAME="Qtum"
    -DAPPVERSION_M=2
    -DAPPVERSION_N=1
    -DAPPVERSION_P=5
    -DAPPVERSION="2.1.5"

    -DOS_IO
    -DOS_IO_SEPROXYHAL
    -DIO_SEPROXYHAL_BUFFER_SIZE_B=72
    -DCOIN_NATIVE_SEGWIT_PREFIX="tq"
    -DBIP44_COIN_TYPE=88
    -DBIP44_COIN_TYPE_2=2301
    -DBIP32_PUBKEY_VERSION=0x0488B21E
    -DCOIN_COINID_SHORT="QTUM"
    -DHAVE_ECC_WEIERSTRASS
    -DHAVE_SECP256K1_CURVE
    -DCOIN_P2PKH_VERSION=58
    -DCOIN_P2SH_VERSION=50
)
set(APP_SOURCES
    ${APP_SRC_DIR}/globals.h
    ${APP_SRC_DIR}/swap/bip32_path.h
    ${APP_SRC_DIR}/swap/handle_check_address.c
    ${APP_SRC_DIR}/swap/bip32_path.c
    ${APP_SRC_DIR}/swap/swap_lib_calls.h
    ${APP_SRC_DIR}/swap/swap_globals.c
    ${APP_SRC_DIR}/swap/swap_globals.h
    ${APP_SRC_DIR}/swap/btchip_bcd.h
    ${APP_SRC_DIR}/swap/handle_check_address.h
    ${APP_SRC_DIR}/swap/btchip_bcd.c
    ${APP_SRC_DIR}/crypto.c
    ${APP_SRC_DIR}/cxram_stash.h
    ${APP_SRC_DIR}/handler/get_master_fingerprint.c
    ${APP_SRC_DIR}/handler/get_extended_pubkey.c
    ${APP_SRC_DIR}/handler/lib/stream_preimage.c
    ${APP_SRC_DIR}/handler/lib/stream_preimage.h
    ${APP_SRC_DIR}/handler/lib/get_merkle_leaf_index.c
    ${APP_SRC_DIR}/handler/lib/get_merkle_preimage.h
    ${APP_SRC_DIR}/handler/lib/get_preimage.h
    ${APP_SRC_DIR}/handler/lib/get_merkle_leaf_hash.h
    ${APP_SRC_DIR}/handler/lib/get_merkleized_map_value_hash.h
    ${APP_SRC_DIR}/handler/lib/get_merkleized_map.c
    ${APP_SRC_DIR}/handler/lib/get_merkle_leaf_element.c
    ${APP_SRC_DIR}/handler/lib/get_merkleized_map_value_hash.c
    ${APP_SRC_DIR}/handler/lib/stream_merkleized_map_value.h
    ${APP_SRC_DIR}/handler/lib/policy.c
    ${APP_SRC_DIR}/handler/lib/stream_merkle_leaf_element.c
    ${APP_SRC_DIR}/handler/lib/get_merkle_leaf_index.h
    ${APP_SRC_DIR}/handler/lib/check_merkle_tree_sorted.h
    ${APP_SRC_DIR}/handler/lib/get_merkle_leaf_element.h
    ${APP_SRC_DIR}/handler/lib/get_merkle_preimage.c
    ${APP_SRC_DIR}/handler/lib/stream_merkleized_map_value.c
    ${APP_SRC_DIR}/handler/lib/get_preimage.c
    ${APP_SRC_DIR}/handler/lib/psbt_parse_rawtx.c
    ${APP_SRC_DIR}/handler/lib/get_merkle_leaf_hash.c
    ${APP_SRC_DIR}/handler/lib/stream_merkle_leaf_element.h
    ${APP_SRC_DIR}/handler/lib/get_merkleized_map_value.h
    ${APP_SRC_DIR}/handler/lib/get_merkleized_map.h
    ${APP_SRC_DIR}/handler/lib/check_merkle_tree_sorted.c
    ${APP_SRC_DIR}/handler/lib/get_merkleized_map_value.c
    ${APP_SRC_DIR}/handler/lib/psbt_parse_rawtx.h
    ${APP_SRC_DIR}/handler/lib/policy.h
    ${APP_SRC_DIR}/handler/sign_psbt/extract_bip32_derivation.c
    ${APP_SRC_DIR}/handler/sign_psbt/update_hashes_with_map_value.c
    ${APP_SRC_DIR}/handler/sign_psbt/extract_bip32_derivation.h
    ${APP_SRC_DIR}/handler/sign_psbt/compare_wallet_script_at_path.c
    ${APP_SRC_DIR}/handler/sign_psbt/compare_wallet_script_at_path.h
    ${APP_SRC_DIR}/handler/sign_psbt/update_hashes_with_map_value.h
    ${APP_SRC_DIR}/handler/sign_message.c
    ${APP_SRC_DIR}/handler/sign_psbt.c
    ${APP_SRC_DIR}/handler/register_wallet.c
    ${APP_SRC_DIR}/handler/client_commands.h
    ${APP_SRC_DIR}/handler/get_wallet_address.c
    ${APP_SRC_DIR}/handler/handlers.h
    ${APP_SRC_DIR}/constants.h
    ${APP_SRC_DIR}/cxram_stash.c
    ${APP_SRC_DIR}/crypto.h
    ${APP_SRC_DIR}/common/bip32.c
    ${APP_SRC_DIR}/common/script.c
    ${APP_SRC_DIR}/common/segwit_addr.h
    ${APP_SRC_DIR}/common/wallet.h
    ${APP_SRC_DIR}/common/write.h
    ${APP_SRC_DIR}/common/read.h
    ${APP_SRC_DIR}/common/varint.h
    ${APP_SRC_DIR}/common/segwit_addr.c
    ${APP_SRC_DIR}/common/format.c
    ${APP_SRC_DIR}/common/buffer.c
    ${APP_SRC_DIR}/common/merkle.c
    ${APP_SRC_DIR}/common/read.c
    ${APP_SRC_DIR}/common/parser.c
    ${APP_SRC_DIR}/common/format.h
    ${APP_SRC_DIR}/common/merkle.h
    ${APP_SRC_DIR}/common/buffer.h
    ${APP_SRC_DIR}/common/bitvector.h
    ${APP_SRC_DIR}/common/wallet.c
    ${APP_SRC_DIR}/common/bip32.h
    ${APP_SRC_DIR}/common/psbt.h
    ${APP_SRC_DIR}/common/parser.h
    ${APP_SRC_DIR}/common/script.h
    ${APP_SRC_DIR}/common/varint.c
    ${APP_SRC_DIR}/common/write.c
    ${APP_SRC_DIR}/common/base58.h
    ${APP_SRC_DIR}/common/base58.c
    ${APP_SRC_DIR}/types.h
    ${APP_SRC_DIR}/boilerplate/io.c
    ${APP_SRC_DIR}/boilerplate/offsets.h
    ${APP_SRC_DIR}/boilerplate/sw.h
    ${APP_SRC_DIR}/boilerplate/constants.h
    ${APP_SRC_DIR}/boilerplate/io.h
    ${APP_SRC_DIR}/boilerplate/dispatcher.c
    ${APP_SRC_DIR}/boilerplate/dispatcher.h
    ${APP_SRC_DIR}/boilerplate/apdu_parser.c
    ${APP_SRC_DIR}/boilerplate/apdu_parser.h
    
    ${APP_SRC_DIR}/commands.h

    ${APP_SRC_DIR}/../fuzzing/ux.h
    
    ${BOLOS_SDK}/lib_standard_app/crypto_helpers.h
    ${BOLOS_SDK}/lib_standard_app/crypto_helpers.c
)

add_executable(fuzz_message
        fuzz_qtum.c
        os_mocks.c
        ${APP_SOURCES}
)

target_include_directories(fuzz_message PUBLIC ../src)
target_compile_options(fuzz_message PUBLIC -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined)
target_link_options(fuzz_message PUBLIC -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=undefined)