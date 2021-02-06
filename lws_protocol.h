#ifndef LWS_PROTOCOL_H
#define LWS_PROTOCOL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define VERSION 0x0002
typedef unsigned char big_num[32];
typedef big_num ed25519_signature;
typedef big_num ed25519_public_key;
typedef big_num blake2b_hash;
typedef big_num sha256_hash;

typedef struct {
    unsigned char uuid[16];
    unsigned char timestamp[4];
    unsigned char desc_size;
    unsigned char *desc;
    uint32_t len;
    char *data;
} TxVchData;

typedef unsigned int (*HookNonceGet)(const void *ctx);
typedef unsigned int (*HookDatetimeGet)(const void *ctx);
typedef int (*HookIDGet)(const void *ctx, unsigned char *id);
typedef int (*HookForkGet)(const void *ctx, big_num fork_out);
typedef int (*HookPublicKeyGet)(const void *ctx, ed25519_public_key pk_out);
typedef int (*HookBlake2bGet)(const void *ctx, const unsigned char *data, const size_t len, blake2b_hash hash);
typedef int (*HookSHA256Get)(const void *ctx, const unsigned char *data, const size_t len, sha256_hash hash);
typedef unsigned int (*HookCRC32Get)(const void *ctx, const unsigned char *data, const size_t len);
typedef int (*HookSignEd25519)(const void *ctx, const unsigned char *data, const size_t len,
                               ed25519_signature signature);

typedef struct {
    void *hook_nonce_context;
    void *hook_datetime_context;
    void *hook_id_context;
    void *hook_fork_context;
    void *hook_public_key_context;
    void *hook_blake2b_context;
    void *hook_sha256_context;
    void *hook_crc32_context;
    void *hook_public_sign_ed25519_context;

    HookNonceGet hook_nonce_get;
    HookDatetimeGet hook_datetime_get;
    HookIDGet hook_id_get;
    HookForkGet hook_fork_get;
    HookPublicKeyGet hook_public_key_get;
    HookBlake2bGet hook_blake2b_get;
    HookSHA256Get hook_sha256_get;
    HookCRC32Get hook_crc32_get;
    HookSignEd25519 hook_public_sign_ed25519;
} LWSProtocolHook;

enum Command { ListUnspent = 0x0011, SendTx = 0x0012 };
typedef struct _LWSProtocol LWSProtocol;

typedef enum {
    LWSPError_CRC32_Different,
    LWSPError_Serialize_Tx_Error,
    LWSPError_Create_Tx_Error,
    LWSPError_Empty_Command_Body,
    LWSPError_Reply_Too_Short,
    LWSPError_HookSHA256GET_NULL,
    LWSPError_HookForkGet_NULL,
    LWSPError_HookPublicKeyGet_NULL,
    LWSPError_HookDatetimeGet_NULL,
    LWSPError_HookNonceGet_NULL,
    LWSPError_HookDevieIDGet_NULL,
    LWSPError_Allocate_Fail,
    LWSPError_Hook_NULL,
    LWSPError_Protocol_NULL,
    LWSPError_ID_Length,
    LWSPError_Success = 0,
} LWSPError;

typedef struct {
    uint16_t version;
    unsigned char hash[32];
    uint16_t error;
    uint16_t command;
} ReplyInfo;

size_t protocol_utils_hex2bin(const char *hex, unsigned char *bin);
void protocol_utils_reverse(void *data, size_t size);

LWSPError protocol_new(const LWSProtocolHook *hook, LWSProtocol **protocol);
LWSPError protocol_listunspent_request(LWSProtocol *protocol, sha256_hash hash, unsigned char *data, size_t *length);
LWSPError protocol_sendtx_request(LWSProtocol *protocol, const unsigned char *address, const TxVchData *vch,
                                  sha256_hash hash, unsigned char *data, size_t *length);
LWSPError protocol_reply_info(LWSProtocol *protocol, const unsigned char *data, const size_t length, ReplyInfo *info);
LWSPError protocol_listunspent_reply_handle(LWSProtocol *protocol, const unsigned char *data, const size_t len);
LWSPError protocol_sendtx_reply_handle(LWSProtocol *protocol, const unsigned char *data, const size_t len);
LWSPError protocol_delete(LWSProtocol *protocol);

#ifdef __cplusplus
}
#endif
#endif