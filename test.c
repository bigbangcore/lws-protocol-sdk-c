#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include "crc32.h"
#include "lws_protocol.h"

static int hook_did_get(const void *context, unsigned char *id)
{
    char device_id[12] = {253, 255, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13};
    memcpy(id, device_id, 12);

    return 12;
}

static unsigned int hook_nonce_get(const void *context) { return 101; }

static int hook_public_key_get(const void *context, ed25519_public_key key)
{
    const char *public_key_hex = "9a6501818596c03a0f5a982e366801e7be9386f5134a0a698fe6dd6c0e50ac8c"; // form bbc node
    key[0] = 0x01;
    sodium_hex2bin(key + 1, 32, public_key_hex, 64, NULL, NULL, NULL);

    return 0;
}

static int hook_fork_get(const void *context, big_num fork)
{
    const char *fork_hex = "0000000006854ebdc236f48dbbe5c87312ea0abd7398888374b5ee9a5eb1d291";
    sodium_hex2bin(fork, 32, fork_hex, 64, NULL, NULL, NULL);

    return 0;
}

static int hook_sha256_get(const void *context, const unsigned char *data, size_t len, sha256_hash hash)
{
    return crypto_hash_sha256(hash, data, len);
}

static unsigned int hook_crc32_get(const void *context, const unsigned char *data, const size_t len)
{
    return crc32(data, len);
}

static int hook_sign_ed25519(const void *ctx, const unsigned char *data, const size_t len, ed25519_signature signature)
{
    return 0;
}

int main(int argc, char **argv)
{
    LWSProtocolHook hook;
    hook.hook_id_get = hook_did_get;
    hook.hook_nonce_get = hook_nonce_get;
    hook.hook_public_key_get = hook_public_key_get;
    hook.hook_fork_get = hook_fork_get;
    hook.hook_sha256_get = hook_sha256_get;
    hook.hook_crc32_get = hook_crc32_get;
    hook.hook_public_sign_ed25519 = hook_sign_ed25519;

    LWSProtocol *protocol = NULL;
    LWSPError error = protocol_new(&hook, &protocol);
    printf("porotocol error:%d\n", error);

    sha256_hash hash;
    unsigned char listunspent_request[1024];
    size_t length = 0;
    error = protocol_listunspent_request(protocol, hash, listunspent_request, &length);
    char hex[length * 2 + 1];
    memset(hex, 0x00, length * 2 + 1);
    sodium_bin2hex(hex, length * 2 + 1, listunspent_request, length);
    printf("listunspent error:%d, length:%ld, hex:%s\n", error, length, hex);

    if (NULL != protocol) {
        error = protocol_delete(protocol);
    }

    return EXIT_SUCCESS;
}