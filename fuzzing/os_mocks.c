#include "cx.h"
#include "os_io.h"
#include "os_io_seproxyhal.h"

void os_longjmp(unsigned int exception) {
    longjmp(try_context_get()->jmp_buf, exception);
}

typedef struct dispatcher_context_s dispatcher_context_t;
try_context_t *current_context = NULL;
try_context_t *try_context_get(void) {
    return current_context;
}

try_context_t *try_context_set(try_context_t *ctx) {
    try_context_t *previous_ctx = current_context;
    current_context = ctx;
    return previous_ctx;
}

cx_err_t cx_ripemd160_init_no_throw(cx_ripemd160_t *hash) {
    return CX_OK;
}

size_t cx_hash_get_size(const cx_hash_t *ctx) {
    return 32;
}

cx_err_t cx_sha256_init_no_throw(cx_sha256_t *hash) {
    return CX_OK;
}

cx_err_t cx_hash_no_throw(cx_hash_t *hash, uint32_t mode, const uint8_t *in, size_t len, uint8_t *out, size_t out_len) {
    return CX_OK;
}

unsigned int pic(unsigned int linked_address) {
    return linked_address;
}


typedef struct internalStorage_t {
    bool dataAllowed;
    bool initialized;
} internalStorage_t;
const internalStorage_t N_storage_real;

#define N_storage (*(volatile internalStorage_t *) PIC(&N_storage_real))





// longest supported policy in V1 is "sh(wsh(sortedmulti(5,@0,@1,@2,@3,@4)))", 38 bytes
#define MAX_DESCRIPTOR_TEMPLATE_LENGTH_V1 40
#define MAX_WALLET_NAME_LENGTH 64

typedef struct {
    uint8_t version;  // supported values: WALLET_POLICY_VERSION_V1 and WALLET_POLICY_VERSION_V2
    uint8_t name_len;
    uint16_t descriptor_template_len;
    char name[MAX_WALLET_NAME_LENGTH + 1];
    union {
        char descriptor_template[MAX_DESCRIPTOR_TEMPLATE_LENGTH_V1];  // used in V1
        uint8_t descriptor_template_sha256[32];                       // used in V2
    };
    size_t n_keys;
    uint8_t keys_info_merkle_root[32];  // root of the Merkle tree of the keys information
} policy_map_wallet_header_t;

unsigned short io_exchange(unsigned char channel_and_flags, unsigned short tx_len) {
    return 0;
}

bool ui_validate_transaction(dispatcher_context_t *context, const char *coin_name, uint64_t fee, bool is_self_transfer, bool sign_sender) {
    return true;
}

bool ui_post_processing_confirm_transaction(dispatcher_context_t *context, bool success) {
    return true;
}

bool ui_validate_output(dispatcher_context_t *context, int index, int total_count, const char *address_or_description, const char *coin_name, uint64_t amount) {
    return true;
}

bool ui_warn_external_inputs(dispatcher_context_t *context){
    return true;
}


bool ui_warn_contract_data(dispatcher_context_t *context) {
    return true;
}

bool ui_warn_nondefault_sighash(dispatcher_context_t *context) {
    return true;
}

bool ui_warn_unverified_segwit_inputs(dispatcher_context_t *context) {
    return true;
}

bool ui_post_processing_confirm_wallet_spend(dispatcher_context_t *context, bool success){
    return true;
}

bool ui_authorize_wallet_spend(dispatcher_context_t *context, const char *wallet_name) {
    return true;
}

bool ui_display_policy_map_cosigner_pubkey(dispatcher_context_t *dispatcher_context, const char *pubkey, uint8_t cosigner_index, uint8_t n_keys, bool is_internal) {
    return true;
}

bool ui_display_message_hash(dispatcher_context_t *context, const char *bip32_path_str, const char *message_hash) {
    return true;
}
bool ui_display_wallet_address(dispatcher_context_t *context, const char *wallet_name, const char *address) {
    return true;
}
bool ui_post_processing_confirm_message(dispatcher_context_t *context, bool success) {
    return true;
}

bool ui_display_pubkey(dispatcher_context_t *context, const char *bip32_path_str, bool is_path_suspicious, const char *pubkey) {
    return true;
}

bool ui_display_register_wallet(dispatcher_context_t *context, const policy_map_wallet_header_t *wallet_header, const char *policy_descriptor) {
    return true;
}

bool ui_post_processing_confirm_wallet_registration(dispatcher_context_t *context, bool success) {
    return true;
}

bolos_bool_t os_global_pin_is_validated()
{
    return BOLOS_UX_OK;
}

unsigned char G_io_apdu_buffer[260];

io_seph_app_t G_io_app;

unsigned char G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];

unsigned int io_seph_is_status_sent(void){
    return 0;
}

void io_seproxyhal_general_status(void){}

void io_seph_send(const unsigned char *buffer, unsigned short length){}

unsigned short io_seph_recv(unsigned char *buffer, unsigned short maxlength, unsigned int flags){
    return 0;
}

// Secure memory comparison
char os_secure_memcmp(void WIDE *src1, void WIDE *src2, unsigned int length) {
    return true;
}

int call_get_preimage(dispatcher_context_t *dispatcher_context, const uint8_t *hash, uint8_t *out, size_t out_len){
    return 64;
}

void halt(void){}


int cx_ecschnorr_sign_no_throw() {
    return 0;
}


size_t cx_hash_sha256(const uint8_t *in, size_t len, uint8_t *out, size_t out_len){
    return 32;
}

int cx_hmac_sha256() {
    return 32;
}

cx_err_t cx_sha256_update(cx_sha256_t *ctx, const uint8_t *data, size_t len){
    return CX_OK;
}

cx_err_t cx_sha256_final(cx_sha256_t *ctx, uint8_t *digest){
    return CX_OK;
}

cx_err_t cx_math_cmp_no_throw(const uint8_t *a, const uint8_t *b, size_t length, int *diff){
    return CX_OK;
}

size_t cx_hmac_sha512(const uint8_t *key,
                      size_t         key_len,
                      const uint8_t *in,
                      size_t         len,
                      uint8_t       *mac,
                      size_t         mac_len){
                        return 64;
                      }

cx_err_t cx_ecfp_scalar_mult_no_throw(cx_curve_t curve, uint8_t *P, const uint8_t *k, size_t k_len){
    return CX_OK;
}

cx_err_t cx_ecfp_add_point_no_throw(cx_curve_t     curve,
                                    uint8_t       *R,
                                    const uint8_t *P,
                                    const uint8_t *Q){
                                        return CX_OK;
                                    }

cx_err_t cx_ripemd160_update(cx_ripemd160_t *ctx, const uint8_t *data, size_t len){
    return CX_OK;
}

cx_err_t cx_ripemd160_final(cx_ripemd160_t *ctx, uint8_t *digest){
    return CX_OK;
}

cx_err_t cx_math_powm_no_throw(uint8_t       *r,
                               const uint8_t *a,
                               const uint8_t *e,
                               size_t         len_e,
                               const uint8_t *m,
                               size_t         len){
                                return CX_OK;
                               }

cx_err_t cx_math_addm_no_throw(uint8_t       *r,
                               const uint8_t *a,
                               const uint8_t *b,
                               const uint8_t *m,
                               size_t         len){
                                return CX_OK;
                               }

cx_err_t cx_math_sub_no_throw(uint8_t *r, const uint8_t *a, const uint8_t *b, size_t len){
    return CX_OK;
}

void os_perso_derive_node_with_seed_key(unsigned int        mode,
                                        cx_curve_t          curve,
                                        const unsigned int *path,
                                        unsigned int        pathLength,
                                        unsigned char      *privateKey,
                                        unsigned char      *chain,
                                        unsigned char      *seed_key,
                                        unsigned int        seed_key_length)
{}

cx_err_t cx_ecdsa_sign_no_throw(const cx_ecfp_private_key_t *pvkey,
                                uint32_t                     mode,
                                cx_md_t                      hashID,
                                const uint8_t               *hash,
                                size_t                       hash_len,
                                uint8_t                     *sig,
                                size_t                      *sig_len,
                                uint32_t                    *info){
                                    return CX_OK;
                                }

cx_err_t cx_ecfp_generate_pair_no_throw(cx_curve_t             curve,
                                        cx_ecfp_public_key_t  *pubkey,
                                        cx_ecfp_private_key_t *privkey,
                                        bool                   keepprivate){
                                            return CX_OK;
                                        }

cx_err_t cx_ecdomain_parameters_length(cx_curve_t cv, size_t *length){
    return CX_OK;
}

cx_err_t cx_ecfp_init_private_key_no_throw(cx_curve_t             curve,
                                           const uint8_t         *rawkey,
                                           size_t                 key_len,
                                           cx_ecfp_private_key_t *pvkey)
{
    return CX_OK;
}

cx_err_t bip32_derive_with_seed_get_pubkey_256(unsigned int    derivation_mode,
                                                                  cx_curve_t      curve,
                                                                  const uint32_t *path,
                                                                  size_t          path_len,
                                                                  uint8_t  raw_pubkey[static 65],
                                                                  uint8_t *chain_code,
                                                                  cx_md_t  hashID,
                                                                  unsigned char *seed,
                                                                  size_t         seed_len)
{
    return CX_OK;
}

cx_err_t cx_ecdsa_sign_rs_no_throw(const cx_ecfp_private_key_t *key,
                                   uint32_t                     mode,
                                   cx_md_t                      hashID,
                                   const uint8_t               *hash,
                                   size_t                       hash_len,
                                   size_t                       rs_len,
                                   uint8_t                     *sig_r,
                                   uint8_t                     *sig_s,
                                   uint32_t                    *info)
{
    return CX_OK;
}

cx_err_t cx_eddsa_sign_no_throw(const cx_ecfp_private_key_t *pvkey,
                                cx_md_t                      hashID,
                                const uint8_t               *hash,
                                size_t                       hash_len,
                                uint8_t                     *sig,
                                size_t                       sig_len)
{
    return CX_OK;
}