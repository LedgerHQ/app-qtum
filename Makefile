# ****************************************************************************
#    Ledger App for Bitcoin
#    (c) 2023 Ledger SAS.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ****************************************************************************

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.defines

# TODO: compile with the right path restrictions

# Application allowed derivation curves.
CURVE_APP_LOAD_PARAMS = secp256k1

# Application allowed derivation paths.
PATH_APP_LOAD_PARAMS = ""
APP_LOAD_PARAMS += --path_slip21 "LEDGER-Wallet policy"

# Application version
APPVERSION_M = 3
APPVERSION_N = 0
APPVERSION_P = 2
APPVERSION   = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"

# Setting to allow building variant applications
VARIANT_PARAM = COIN
VARIANT_VALUES = qtum_testnet qtum

# simplify for tests
ifndef COIN
COIN=qtum_testnet
endif

########################################
#     Application custom permissions   #
########################################
HAVE_APPLICATION_FLAG_BOLOS_SETTINGS = 1
HAVE_APPLICATION_FLAG_LIBRARY = 1

# Enables direct data signing without having to specify it in the settings.
ALLOW_DATA?=0
ifneq ($(ALLOW_DATA),0)
DEFINES += HAVE_ALLOW_DATA
endif

ifeq ($(COIN),qtum_testnet)

# Qtum testnet, no legacy support
DEFINES   += BIP32_PUBKEY_VERSION=0x043587CF
DEFINES   += BIP44_COIN_TYPE=1
DEFINES   += BIP44_COIN_TYPE_2=1
DEFINES   += COIN_P2PKH_VERSION=120
DEFINES   += COIN_P2SH_VERSION=110
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"tq\"
DEFINES   += COIN_COINID_SHORT=\"TEST\"

APPNAME = "Qtum Test"
PATH_APP_LOAD_PARAMS = "44'/1'" "45'/1'" "48'/1'" "49'/1'" "84'/1'" "86'/1'" "0'/45342'" "20698'/3053'/12648430'"

else ifeq ($(COIN),qtum)

# Qtum mainnet, no legacy support
DEFINES   += BIP32_PUBKEY_VERSION=0x0488B21E
DEFINES   += BIP44_COIN_TYPE=88
DEFINES   += BIP44_COIN_TYPE_2=2301
DEFINES   += COIN_P2PKH_VERSION=58
DEFINES   += COIN_P2SH_VERSION=50
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"qc\"
DEFINES   += COIN_COINID_SHORT=\"QTUM\"

APPNAME = "Qtum"
PATH_APP_LOAD_PARAMS = "44'/88'" "45'/88'" "48'/88'" "49'/88'" "84'/88'" "86'/88'" "44'/2301'" "45'/2301'" "48'/2301'" "49'/2301'" "84'/2301'" "86'/2301'" "0'/45342'" "20698'/3053'/12648430'"

else
ifeq ($(filter clean,$(MAKECMDGOALS)),)
$(error Unsupported COIN - use qtum_testnet, qtum)
endif
endif

# Application icons following guidelines:
# https://developers.ledger.com/docs/embedded-app/design-requirements/#device-icon
ICON_NANOS = icons/nanos_app_bitcoin.gif
ICON_NANOX = icons/nanox_app_bitcoin.gif
ICON_NANOSP = icons/nanox_app_bitcoin.gif
ICON_STAX = icons/stax_app_bitcoin.gif

########################################
# Application communication interfaces #
########################################
ENABLE_BLUETOOTH = 1

########################################
#         NBGL custom features         #
########################################
ENABLE_NBGL_QRCODE = 1

########################################
#          Features disablers          #
########################################
# Don't use standard app file to avoid conflicts for now
DISABLE_STANDARD_APP_FILES = 1

# Don't use default IO_SEPROXY_BUFFER_SIZE to use another
# value for NANOS for an unknown reason.
DISABLE_DEFAULT_IO_SEPROXY_BUFFER_SIZE = 1

# Don't use STANDARD_USB as we want IO_USB_MAX_ENDPOINTS=4
# and the default is 6
DISABLE_STANDARD_USB = 1

DEFINES   += HAVE_IO_USB HAVE_L4_USBLIB IO_USB_MAX_ENDPOINTS=4 IO_HID_EP_LENGTH=64 HAVE_USB_APDU
DEFINES   += HAVE_BOLOS_APP_STACK_CANARY


ifeq ($(TARGET_NAME),TARGET_NANOS)
DEFINES       += IO_SEPROXYHAL_BUFFER_SIZE_B=72
DEFINES       += HAVE_WALLET_ID_SDK
else
DEFINES       += IO_SEPROXYHAL_BUFFER_SIZE_B=300
endif

ifeq ($(TARGET_NAME),TARGET_NANOS)
    # enables optimizations using the shared 1K CXRAM region
    DEFINES   += USE_CXRAM_SECTION
endif

# debugging helper functions and macros
CFLAGS    += -include debug-helpers/debug.h

# DEFINES   += HAVE_PRINT_STACK_POINTER

ifeq ($(DEBUG),10)
    $(warning Using semihosted PRINTF. Only run with speculos!)
    DEFINES   += HAVE_PRINTF HAVE_SEMIHOSTED_PRINTF PRINTF=semihosted_printf
endif

# Needed to be able to include the definition of G_cx
INCLUDES_PATH += $(BOLOS_SDK)/lib_cxng/src

# Application source files
APP_SOURCE_PATH += src
SDK_SOURCE_PATH += lib_stusb lib_stusb_impl

# Allow usage of function from lib_standard_app/crypto_helpers.c
INCLUDES_PATH  += ${BOLOS_SDK}
APP_SOURCE_FILES += ${BOLOS_SDK}/lib_standard_app/crypto_helpers.c

include $(BOLOS_SDK)/Makefile.standard_app

# Makes a detailed report of code and data size in debug/size-report.txt
# More useful for production builds with DEBUG=0
size-report: bin/app.elf
	arm-none-eabi-nm --print-size --size-sort --radix=d bin/app.elf >debug/size-report.txt
