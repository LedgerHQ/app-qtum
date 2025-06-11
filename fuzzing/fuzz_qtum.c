#include "boilerplate/apdu_parser.h"
#include "boilerplate/constants.h"
#include "boilerplate/dispatcher.h"

#include "handler/handlers.h"
#include "commands.h"

#include "os_io.h"
#include "os_io_seproxyhal.h"

#define CLA_APP 0xE1

const command_descriptor_t COMMAND_DESCRIPTORS[] = {
    {
        .cla = CLA_APP,
        .ins = GET_EXTENDED_PUBKEY,
        .handler = (command_handler_t)handler_get_extended_pubkey
    },
    {
        .cla = CLA_APP,
        .ins = GET_WALLET_ADDRESS,
        .handler = (command_handler_t)handler_get_wallet_address
    },
    {
        .cla = CLA_APP,
        .ins = REGISTER_WALLET,
        .handler = (command_handler_t)handler_register_wallet
    },
    {
        .cla = CLA_APP,
        .ins = SIGN_PSBT,
        .handler = (command_handler_t)handler_sign_psbt
    },
    {
        .cla = CLA_APP,
        .ins = GET_MASTER_FINGERPRINT,
        .handler = (command_handler_t)handler_get_master_fingerprint
    },
    {
        .cla = CLA_APP,
        .ins = SIGN_MESSAGE,
        .handler = (command_handler_t)handler_sign_message
    },
    {
        .cla = CLA_APP,
        .ins = SIGN_SENDER_PSBT,
        .handler = (command_handler_t)handler_sign_sender_psbt
    },
};

dispatcher_context_t G_dispatcher_context;

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

    command_t cmd;
    memset(&cmd, 0, sizeof(cmd));
    
    // Command parsing
    if (!apdu_parser(&cmd, Data, Size)) {
        // Bad length
        return 1;
    }
    
    if (cmd.cla != CLA_APP) {
        // Wrong CLA
        return 2;
    }

    if (cmd.ins != GET_EXTENDED_PUBKEY && cmd.ins != GET_WALLET_ADDRESS &&
                cmd.ins != SIGN_PSBT && cmd.ins != GET_MASTER_FINGERPRINT &&
                cmd.ins != SIGN_SENDER_PSBT) {
        // Unsupported INS type
        return 3;
    }

    // Call the dispatcher
    apdu_dispatcher(COMMAND_DESCRIPTORS,
                    sizeof(COMMAND_DESCRIPTORS) / sizeof(COMMAND_DESCRIPTORS[0]),
                    NULL,
                    &cmd);
    return 0;
}