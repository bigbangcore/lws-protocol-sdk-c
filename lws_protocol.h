#ifndef LWS_PROTOCOL_H
#define LWS_PROTOCOL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef unsigned char big_num[32];
typedef big_num ed25519_signature;
typedef big_num ed25519_public_key;
// typedef big_num ed25519_secret_key;
// typedef big_num curve25519_key;
// typedef big_num key_seed;
// typedef big_num shared_key;
typedef big_num blake2b_hash;

// typedef struct _ServiceReply ServiceReply;
// typedef struct _SyncReply SyncReply;

// typedef struct {
//     uint16_t nonce;
//     uint32_t version;
//     uint32_t address_id;
//     unsigned char fork_bitmap[8];
//     key_seed seed;
// } ServiceResult;

// typedef struct {
//     uint16_t nonce;
//     unsigned char block_hash[32];
//     uint32_t block_height;
//     uint32_t block_time;
//     uint16_t utxo_num;
//     uint8_t continue_flag;
// } SyncResult;

// typedef struct {
//     uint16_t nonce;
//     uint8_t error;
//     uint8_t err_code;
//     char txid[65];
//     char *err_desc;
// } SendTxResult;

typedef struct {
    unsigned char uuid[16];
    unsigned char timestamp[4];
    unsigned char desc_size;
    unsigned char *desc;
    uint32_t len;
    char *data;
} VchData;

// typedef unsigned int (*NonceGet)(const void *ctx);
// typedef unsigned int (*DatetimeGet)(const void *ctx);
// typedef int (*DeviceIDGet)(const void *ctx, char *id);
// typedef int (*ForkGet)(const void *ctx, big_num fork_out);
// typedef int (*PublicKeyGet)(const void *ctx, ed25519_public_key pk_out);
// typedef int (*SharedKeyGet)(const void *ctx, const key_seed seed, const unsigned char *data, const size_t size,
//                             shared_key key);
// typedef int (*Blake2bGet)(const void *ctx, const unsigned char *data, const size_t len, blake2b_hash hash);
// typedef int (*SignEd25519)(const void *ctx, const unsigned char *data, const size_t len, ed25519_signature
// signature);

// // 注册用户回调函数
// // int hook_nonce_get(const NonceGet callback, void *ctx);
// // int hook_datetime_get(const DatetimeGet callback, void *ctx);
// // int hook_device_id_get(const DeviceIDGet callback, void *ctx);
// // int hook_fork_get(const ForkGet callback, void *ctx);
// // int hook_public_key_get(const PublicKeyGet callback, void *ctx);
// // int hook_shared_key_get(const SharedKeyGet callback, void *ctx);
// // int hook_blake2b_get(const Blake2bGet callback, void *ctx);
// // int hook_public_sign_ed25519(const SignEd25519 callback, void *ctx);

// // 初始化sdk 须在用户回调注册完毕后执行
// int lws_protocol_init();

// // 服务请求/响应
// size_t lws_service_request(unsigned char *data);
// int lws_service_reply_handle(const unsigned char *data, const size_t len, ServiceResult *result);

// // 同步请求/响应
// size_t lws_sync_request(unsigned char *data);
// int lws_sync_reply_handle(const unsigned char *data, const size_t len, SyncResult *result);

// // // 交易请求/响应
// size_t lws_send_tx_request(const char *address_hex, VchData *vch_data, unsigned char *data);
// int lws_send_tx_reply_handle(const unsigned char *data, const size_t len, SendTxResult *result);

// New LWS protocol
#define VERSION 0x0002
typedef big_num sha256_hash;

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
    LWSPError_Empty_Command_Body,
    LWSPError_Reply_Too_Short,
    LWSPError_HookSHA256GET_NULL,
    LWSPError_HookForkGet_NULL,
    LWSPError_HookPublicKeyGet_NULL,
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

LWSPError protocol_new(const LWSProtocolHook *hook, LWSProtocol **protocol);
LWSPError protocol_listunspent_request(LWSProtocol *protocol, sha256_hash hash, unsigned char *data, size_t *length);
LWSPError protocol_sendtx_request(LWSProtocol *protocol, const char *address, const VchData *vch, unsigned char *data,
                                  sha256_hash hash);
LWSPError protocol_reply_info(LWSProtocol *protocol, const unsigned char *data, const size_t length, ReplyInfo *info);
LWSPError protocol_listunspent_reply_handle(LWSProtocol *protocol, const unsigned char *data, const size_t len);
LWSPError protocol_sendtx_reply_handle(LWSProtocol *protocol, const unsigned char *data, const size_t len);
LWSPError protocol_delete(LWSProtocol *protocol);

#ifdef __cplusplus
}
#endif
#endif