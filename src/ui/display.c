/*****************************************************************************
 *   Ledger App Boilerplate.
 *   (c) 2020 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#pragma GCC diagnostic ignored "-Wformat-invalid-specifier"  // snprintf
#pragma GCC diagnostic ignored "-Wformat-extra-args"         // snprintf

#include <stdbool.h>  // bool
#include <stdio.h>    // snprintf
#include <string.h>   // memset

#include "os.h"
#include "ux.h"
#include "glyphs.h"

#include "display.h"
#include "constants.h"
#include "../globals.h"
#include "../boilerplate/io.h"
#include "../boilerplate/sw.h"
#include "../common/bip32.h"
#include "../common/format.h"
#include "../constants.h"

#define MAX_BASE58_PUBKEY_LENGTH 112
#define MAX_ADDRESS_LENGTH 35

// These globals are a workaround for a limitation of the UX library that
// does not allow to pass proper callbacks and context.
static action_validate_cb g_validate_callback;

extern dispatcher_context_t G_dispatcher_context;

// TODO: hard to keep track of what globals are used in the same flows
//       (especially since the same flow step can be shared in different flows)

typedef struct {
    char bip32_path[MAX_SERIALIZED_BIP32_PATH_LENGTH + 1];
    char pubkey[MAX_SERIALIZED_PUBKEY_LENGTH + 1];
} ui_path_and_pubkey_state_t;

typedef struct {
    // TODO: avoid hack: keep bip32_path in the same position in memory for ui_display_pubkey_state_t and ui_display_address_state_t.
    char bip32_path[MAX_SERIALIZED_BIP32_PATH_LENGTH + 1];
    char address[MAX_ADDRESS_LENGTH_STR + 1];
} ui_path_and_address_state_t;

typedef struct {
    char wallet_name[MAX_WALLET_NAME_LENGTH + 1];
    char multisig_type[sizeof("15 of 15")];
    char address[MAX_ADDRESS_LENGTH_STR + 1];
} ui_wallet_state_t;

typedef struct {
    char pubkey[MAX_SERIALIZED_PUBKEY_LENGTH + 1];
    char signer_index[sizeof("Signer 15 of 15")];
} ui_cosigner_pubkey_and_index_state_t;


/**
 * Union of all the states for each of the UI screens, in order to save memory.
 */
typedef union {
    ui_path_and_pubkey_state_t path_and_pubkey;
    ui_path_and_address_state_t path_and_address;
    ui_wallet_state_t wallet;
    ui_cosigner_pubkey_and_index_state_t cosigner_pubkey_and_index;
} ui_state_t;

static ui_state_t g_ui_state;


/*
    STATELESS STEPS
    As these steps do not access per-step globals (except possibly a callback), they can be used in any flow.
*/

// Step with icon and text for pubkey
UX_STEP_NOCB(ux_display_confirm_pubkey_step, pn, {&C_icon_eye, "Confirm public key"});

// Step with icon and text for address
UX_STEP_NOCB(ux_display_confirm_address_step, pn, {&C_icon_eye, "Confirm receive address"});

// Step with icon and text for a suspicious address
UX_STEP_NOCB(
    ux_display_unusual_derivation_path_step,
    pnn,
    {
      &C_icon_warning,
      "The derivation",
      "path is unusual!",
    });

// Step with icon and text to caution the user to reject if unsure
UX_STEP_CB(
    ux_display_reject_if_not_sure_step,
    pnn,
    (*g_validate_callback)(&G_dispatcher_context, false),
    {
      &C_icon_crossmark,
      "Reject if you're",
      "not sure",
    });

// Step with approve button
UX_STEP_CB(ux_display_approve_step,
           pb,
           (*g_validate_callback)(&G_dispatcher_context, true),
           {
               &C_icon_validate_14,
               "Approve",
           });

// Step with reject button
UX_STEP_CB(ux_display_reject_step,
           pb,
           (*g_validate_callback)(&G_dispatcher_context, false),
           {
               &C_icon_crossmark,
               "Reject",
           });


/*
    STATEFUL STEPS
    These can only be used in the context of specific flows, as they access a common shared space for strings.
*/

// PATH/PUBKEY or PATH/ADDRESS 

// Step with title/text for BIP32 path
UX_STEP_NOCB(ux_display_path_step,
             bnnn_paging,
             {
                 .title = "Path",
                 .text = g_ui_state.path_and_pubkey.bip32_path,
             });

// Step with title/text for pubkey
UX_STEP_NOCB(ux_display_pubkey_step,
             bnnn_paging,
             {
                 .title = "Public key",
                 .text = g_ui_state.path_and_pubkey.pubkey,
             });

// Step with title/text for address
UX_STEP_NOCB(ux_display_address_step,
             bnnn_paging,
             {
                 .title = "Address",
                 .text = g_ui_state.path_and_address.address,
             });


// Step with icon and text with name of a wallet being registered
UX_STEP_NOCB(ux_display_wallet_header_name_step,
             pnn,
             {
               &C_icon_wallet,
               "Register wallet",
               g_ui_state.wallet.wallet_name,
             });

// Step with description of a m-of-n multisig wallet
UX_STEP_NOCB(ux_display_wallet_multisig_type_step,
             nn,
             {
               "Multisig wallet",
               g_ui_state.wallet.multisig_type,
             });


// Step with index and xpub of a cosigner of a multisig wallet
UX_STEP_NOCB(
    ux_display_wallet_multisig_cosigner_pubkey_step,
    bnnn_paging,
    {
        .title = g_ui_state.cosigner_pubkey_and_index.signer_index,
        .text = g_ui_state.cosigner_pubkey_and_index.pubkey,
    });



// Step with icon and text with name of a wallet being registered
UX_STEP_NOCB(ux_display_wallet_name_step,
             pnn,
             {
               &C_icon_wallet,
               "Receive in:",
               g_ui_state.wallet.wallet_name,
             });

// Step with title/text for address, used when showing a wallet receive address
UX_STEP_NOCB(ux_display_wallet_address_step,
             bnnn_paging,
             {
                 .title = "Address",
                 .text = g_ui_state.wallet.address,
             });


// FLOW to display BIP32 path and pubkey:
// #1 screen: eye icon + "Confirm Pubkey"
// #2 screen: display BIP32 Path
// #3 screen: display pubkey
// #4 screen: approve button
// #5 screen: reject button
UX_FLOW(ux_display_pubkey_flow,
        &ux_display_confirm_pubkey_step,
        &ux_display_path_step,
        &ux_display_pubkey_step,
        &ux_display_approve_step,
        &ux_display_reject_step);


// FLOW to display a receive address, for a standard path:
// #1 screen: eye icon + "Confirm Address"
// #3 screen: display address
// #4 screen: approve button
// #5 screen: reject button
UX_FLOW(ux_display_address_flow,
        &ux_display_confirm_address_step,
        &ux_display_address_step,
        &ux_display_approve_step,
        &ux_display_reject_step);


// FLOW to display a receive address, for a non-standard path:
// #1 screen: warning icon + "The derivation path is unusual!"
// #2 screen: display BIP32 Path
// #3 screen: crossmark icon + "Reject if not sure" (user can reject here)
// #4 screen: eye icon + "Confirm Address"
// #5 screen: display address
// #6 screen: approve button
// #7 screen: reject button
UX_FLOW(ux_display_address_suspicious_flow,
        &ux_display_unusual_derivation_path_step,
        &ux_display_path_step,
        &ux_display_reject_if_not_sure_step,
        &ux_display_confirm_address_step,
        &ux_display_address_step,
        &ux_display_approve_step,
        &ux_display_reject_step);


// FLOW to display the header of a multisig wallet:
// #1 screen: eye icon + "Register multisig" and the wallet name
// #2 screen: display multisig threshold and number of keys
// #3 screen: approve button
// #4 screen: reject button
UX_FLOW(ux_display_multisig_header_flow,
        &ux_display_wallet_header_name_step,
        &ux_display_wallet_multisig_type_step,
        &ux_display_approve_step,
        &ux_display_reject_step);


// FLOW to display the header of a multisig wallet:
// #1 screen: Cosigner index and pubkey (paginated)
// #2 screen: approve button
// #3 screen: reject button
UX_FLOW(ux_display_multisig_cosigner_pubkey_flow,
        &ux_display_wallet_multisig_cosigner_pubkey_step,
        &ux_display_approve_step,
        &ux_display_reject_step);



// FLOW to display the name and a receive address of a registered wallet:
// #1 screen: wallet name
// #1 screen: wallet address
// #2 screen: approve button
// #3 screen: reject button
UX_FLOW(ux_display_wallet_name_address_flow,
        &ux_display_wallet_name_step,
        &ux_display_wallet_address_step,
        &ux_display_approve_step,
        &ux_display_reject_step);


int ui_display_pubkey(dispatcher_context_t *context, char *bip32_path, char *pubkey, action_validate_cb callback) {
    ui_path_and_pubkey_state_t *state = (ui_path_and_pubkey_state_t *)&g_ui_state;

    strncpy(state->bip32_path, bip32_path, sizeof(state->bip32_path));
    strncpy(state->pubkey, pubkey, sizeof(state->pubkey));

    g_validate_callback = callback;

    ux_flow_init(0, ux_display_pubkey_flow, NULL);

    return 0;
}


int ui_display_address(dispatcher_context_t *context, char *address, bool is_path_suspicious, char *path_str, action_validate_cb callback) {
    ui_path_and_address_state_t *state = (ui_path_and_address_state_t *)&g_ui_state;

    strncpy(state->address, address, sizeof(state->address));

    g_validate_callback = callback;

    if (!is_path_suspicious) {
        ux_flow_init(0, ux_display_address_flow, NULL);
    } else {
        strncpy(state->bip32_path, path_str, sizeof(state->bip32_path));
        ux_flow_init(0, ux_display_address_suspicious_flow, NULL);
    }
    return 0;
}


int ui_display_multisig_header(dispatcher_context_t *context, char *wallet_name, uint8_t threshold, uint8_t n_keys, action_validate_cb callback) {
    ui_wallet_state_t *state = (ui_wallet_state_t *)&g_ui_state;

    strncpy(state->wallet_name, wallet_name, sizeof(state->wallet_name));
    snprintf(state->multisig_type, sizeof(state->multisig_type), "%u of %u", threshold, n_keys);

    g_validate_callback = callback;

    ux_flow_init(0, ux_display_multisig_header_flow, NULL);
    return 0;
}


int ui_display_multisig_cosigner_pubkey(dispatcher_context_t *context, char *pubkey, uint8_t cosigner_index, uint8_t n_keys, action_validate_cb callback) {
    ui_cosigner_pubkey_and_index_state_t *state = (ui_cosigner_pubkey_and_index_state_t *)&g_ui_state;

    strncpy(state->pubkey, pubkey, sizeof(state->pubkey));
    snprintf(state->signer_index, sizeof(state->signer_index), "Signer %u of %u", cosigner_index, n_keys);

    g_validate_callback = callback;

    ux_flow_init(0, ux_display_multisig_cosigner_pubkey_flow, NULL);
    return 0;
}


int ui_display_wallet_address(dispatcher_context_t *context, char *wallet_name, char *address, action_validate_cb callback) {
    ui_wallet_state_t *state = (ui_wallet_state_t *)&g_ui_state;

    strncpy(state->wallet_name, wallet_name, sizeof(state->wallet_name));
    strncpy(state->address, address, sizeof(state->address));

    g_validate_callback = callback;

    ux_flow_init(0, ux_display_wallet_name_address_flow, NULL);
    return 0;
}
