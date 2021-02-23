#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <getopt.h>
#include <fcntl.h>
#include <sodium.h>
#include <mosquitto.h>
#include "crc32.h"
#include "uuid4.h"
#include "lws_protocol.h"

static char device_id[12] = {253, 255, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13};
static char id[sizeof(device_id) * 2 + 1];
static struct mosquitto *mosq;
static int run = 1;
static int connected = 0;

static struct RequestBuffer {
    pthread_mutex_t lock;
    int flag;  // 0-已处理; 1-未处理
    int index; //该消息发送次数
    size_t length;
    unsigned char buff[1024];
    unsigned char hash[32];
} buff;

/**
 * @brief  message_sender
 * 用户自定义消息发送函数
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2021/2/6 13:43:46
 * @param  struct mosquitto * mosq
 * @param  const unsigned char * data
 * @param  const size_t     length
 * @param  const unsigned char * hash
 * @return static int
 */
static int message_sender(struct mosquitto *mosq, const unsigned char *data, const size_t length,
                          const unsigned char *hash)
{
    char hex[32 * 2 + 1];
    memset(hex, 0x00, 32 * 2 + 1);
    sodium_bin2hex(hex, 32 * 2 + 1, hash, 32);
    // printf("message_sender hash:%s\n", hex);

    // 发送数据
    pthread_mutex_lock(&buff.lock);
    buff.flag = 1;
    buff.length = length;
    memcpy(&buff.buff, data, length);
    memcpy(&buff.hash, hash, 32);

    int ret = mosquitto_publish(mosq, NULL, "lws-test-topic", length, data, 0, 0);
    if (MOSQ_ERR_SUCCESS != ret) {
        pthread_mutex_unlock(&buff.lock);
        return ret;
    }
    pthread_mutex_unlock(&buff.lock);

    // 检查是否正确处理
    int i;
    for (i = 0; i < 10000; i++) {
        pthread_mutex_lock(&buff.lock);
        if (1 == buff.flag) {
            pthread_mutex_unlock(&buff.lock);
            usleep(10 * 1000);

            continue;
        }
        pthread_mutex_unlock(&buff.lock);

        return 0; // 成功
    }

    // 超时处理
    pthread_mutex_lock(&buff.lock);
    buff.index = 0;
    buff.flag = 0;
    buff.length = 0;
    memset(&buff.buff, 0x00, 1024);
    memset(&buff.hash, 0x00, 32);
    pthread_mutex_unlock(&buff.lock);

    return 40; //超时
}

/**
 * @brief  message_receiver
 * 用户自定义消息接收函数
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2021/2/6 13:44:49
 * @param  LWSProtocol *    protocol
 * @param  const unsigned char * data
 * @param  const size_t     length
 * @return static int
 */
static int message_receiver(LWSProtocol *protocol, const unsigned char *data, const size_t length)
{
    ReplyInfo info;
    LWSPError error = protocol_reply_info(protocol, data, length, &info);
    if (LWSPError_Success != error) {
        return error;
    }
    printf("version:%d, error:%d, command:%d\n", info.version, info.error, info.command);

    // char hex[32 * 2 + 1];
    // memset(hex, 0x00, 32 * 2 + 1);
    // sodium_bin2hex(hex, 32 * 2 + 1, info.hash, 32);
    // printf("message_receiver hash:%s\n", hex);

    pthread_mutex_lock(&buff.lock);
    if (0 != memcmp(buff.hash, info.hash, 32)) {
        pthread_mutex_unlock(&buff.lock);
        return 41;
    }

    buff.index = 0;
    buff.flag = 0;
    buff.length = 0;
    memset(&buff.buff, 0x00, 1024);
    memset(&buff.hash, 0x00, 32);

    if (0 == info.error && ListUnspent == info.command) {
        error = protocol_listunspent_reply_handle(protocol, data, length);
    }

    if (0 == info.error && SendTx == info.command) {
        error = protocol_sendtx_reply_handle(protocol, data, length);
    }
    pthread_mutex_unlock(&buff.lock);

    return 0;
}

/**
 * @brief  connect_callback
 * mosquitto 连接回调函数
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2021/2/6 13:45:39
 * @param  struct mosquitto * mosq
 * @param  void *           obj
 * @param  int              result
 * @return static void
 */
static void connect_callback(struct mosquitto *mosq, void *obj, int result)
{
    LWSProtocol *protocol = (LWSProtocol *)obj;
    printf("connect callback, rc=%d\n", result);

    connected = 1;
}

/**
 * @brief  message_callback
 * mosquitto 消息接收回调函数
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2021/2/6 13:46:50
 * @param  struct mosquitto * mosq
 * @param  void *           obj
 * @param  const struct mosquitto_message * message
 * @return static void
 */
static void message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
    LWSProtocol *protocol = (LWSProtocol *)obj;
    char hex[message->payloadlen * 2 + 1];
    memset(hex, 0x00, message->payloadlen * 2 + 1);
    sodium_bin2hex(hex, message->payloadlen * 2 + 1, message->payload, message->payloadlen);

    // printf("got message '%.*s' for topic '%s'\n", message->payloadlen * 2 + 1, hex, message->topic);
    int rc = message_receiver(protocol, message->payload, message->payloadlen);
    // printf("message_callback return:%d\n", rc);
}

static int hook_did_get(const void *context, unsigned char *id)
{
    memcpy(id, device_id, 12);

    return 12;
}

/// LWS Protocol 注册回调函数体

/**
 * @brief  hook_nonce_get
 * 随机数获取
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2021/2/6 13:49:6
 * @param  const void *     context
 * @return static unsigned int
 */
static unsigned int hook_nonce_get(const void *context) { return 101; }

/**
 * @brief  hook_datetime_get
 * 时间获取
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2021/2/6 13:49:24
 * @param  const void *     context
 * @return static unsigned int
 */
static unsigned int hook_datetime_get(const void *context)
{
    time_t now;
    time(&now);
    return now;
}

/**
 * @brief  hook_public_key_get
 * 目标公钥获取
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2021/2/6 13:50:23
 * @param  const void *     context
 * @param  ed25519_public_key  key
 * @return static int
 */
static int hook_public_key_get(const void *context, ed25519_public_key key)
{
    const char *public_key_hex = "e0b440ccdf4f2d014595e6fdec6e0cb38e18d08d2742ff777c012c4ea43ab588"; // form bbc node
    key[0] = 0x01;
    protocol_utils_hex2bin(public_key_hex, 64, key + 1);
    protocol_utils_reverse(key + 1, 32); // 正常端序

    return 0;
}

/**
 * @brief  hook_fork_get
 * 交易分支id获取
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2021/2/6 13:51:8
 * @param  const void *     context
 * @param  big_num          fork
 * @return static int
 */
static int hook_fork_get(const void *context, big_num fork)
{
    // const char *fork_hex = "0000001f9a046730bf5102283f43fe51bd1c1b913b3b931c1566d9c5e1463a7e";
    const char *fork_hex = "0000000006854ebdc236f48dbbe5c87312ea0abd7398888374b5ee9a5eb1d291";
    protocol_utils_hex2bin(fork_hex, 64, fork);

    return 0;
}

/**
 * @brief  hook_sha256_get
 * SHA256 hash获取
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2021/2/6 13:51:50
 * @param  const void *     context
 * @param  const unsigned char * data
 * @param  size_t           len
 * @param  sha256_hash      hash
 * @return static int
 */
static int hook_sha256_get(const void *context, const unsigned char *data, size_t len, sha256_hash hash)
{
    return crypto_hash_sha256(hash, data, len);
}

/**
 * @brief  hook_crc32_get
 * crc32获取
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2021/2/6 13:53:0
 * @param  const void *     context
 * @param  const unsigned char * data
 * @param  const size_t     len
 * @return static unsigned int
 */
static unsigned int hook_crc32_get(const void *context, const unsigned char *data, const size_t len)
{
    return crc32(data, len);
}

/**
 * @brief  hook_sign_ed25519
 * ed25519 签名获取
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2021/2/6 13:53:45
 * @param  const void *     ctx
 * @param  const unsigned char * data
 * @param  const size_t     len
 * @param  ed25519_signature  signature
 * @return static int
 */
static int hook_sign_ed25519(const void *ctx, const unsigned char *data, const size_t len, ed25519_signature signature)
{
    const char *private_key_hex = "ec1883605124189bd30f04d123845052f4108ad7975f0d3a50dab22150ae42c5";
    unsigned char key[64];
    unsigned char seed[64];
    protocol_utils_hex2bin(private_key_hex, 64, key);
    protocol_utils_reverse(key, 32); // 正常序列
    crypto_sign_seed_keypair(&key[32], seed, (unsigned char *)key);

    unsigned char hash[32] = {0};
    crypto_generichash_blake2b(hash, sizeof(hash), data, len, NULL, 0);
    crypto_sign_ed25519_detached(signature, NULL, hash, sizeof(hash), key);

    return 0;
}

/**
 * @brief  hook_blake2b_get
 * blake2b hash获取
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2021/2/6 13:54:39
 * @param  const void *     ctx
 * @param  const unsigned char * data
 * @param  const size_t     len
 * @param  blake2b_hash     hash
 * @return static int
 */
static int hook_blake2b_get(const void *ctx, const unsigned char *data, const size_t len, blake2b_hash hash)
{
    crypto_generichash_blake2b(hash, 32, data, len, NULL, 0);
    return 0;
}

/**
 * @brief  mqtt_thread
 * mqtt连接维护进程函数
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2021/2/6 13:55:39
 * @param  LWSProtocol *    protocol
 * @return static void
 */
static void mqtt_thread(LWSProtocol *protocol)
{
    // 设置id
    memset(id, 0x00, sizeof(device_id) * 2 + 1);
    sodium_bin2hex(id, sizeof(device_id) * 2 + 1, device_id, sizeof(device_id));
    printf("id hex:%s\n", id);

    int rc = 0;
    mosquitto_lib_init();
    char *topic = id;
    mosq = mosquitto_new(id, true, (void *)protocol);

    if (NULL == mosq) {
        mosquitto_lib_cleanup();
        return;
    }

    // char *host = "127.0.0.1";
    char *host = "192.168.199.228";
    int port = 1883;
    mosquitto_connect_callback_set(mosq, connect_callback);
    mosquitto_message_callback_set(mosq, message_callback);

    rc = mosquitto_connect(mosq, host, port, 120);
    if (MOSQ_ERR_SUCCESS == rc) {
    }

    int mosq_req_sub_ret = mosquitto_subscribe(mosq, NULL, topic, 0);
    if (MOSQ_ERR_SUCCESS == mosq_req_sub_ret) {
    }

    while (run) {
        rc = mosquitto_loop(mosq, -1, 1);
        if (run && rc) {
            printf("connection error! rc=%d\n", rc);
            sleep(1);
            mosquitto_reconnect(mosq);
        }
    }

    mosquitto_unsubscribe(mosq, NULL, topic);
    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();
}

struct MqttThreadArgument {
    LWSProtocol *protocol;
    char host[128];
    int port;
    char topic[256];
};

/**
 * @brief  mqtt_thread
 * mqtt连接维护进程函数
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2021/2/6 13:55:39
 * @param  LWSProtocol *    protocol
 * @return static void
 */
static void mqtt_thread_1(struct MqttThreadArgument *argument)
{
    LWSProtocol *protocol = argument->protocol;
    int rc = 0;
    mosquitto_lib_init();
    mosq = mosquitto_new(argument->topic, true, (void *)protocol);

    if (NULL == mosq) {
        mosquitto_lib_cleanup();
        return;
    }

    char *host = argument->host;
    int port = argument->port;
    mosquitto_connect_callback_set(mosq, connect_callback);
    mosquitto_message_callback_set(mosq, message_callback);

    rc = mosquitto_connect(mosq, host, port, 120);
    if (MOSQ_ERR_SUCCESS == rc) {
    }

    int mosq_req_sub_ret = mosquitto_subscribe(mosq, NULL, argument->topic, 0);
    if (MOSQ_ERR_SUCCESS == mosq_req_sub_ret) {
    }

    while (run) {
        rc = mosquitto_loop(mosq, -1, 1);
        if (run && rc) {
            printf("connection error! rc=%d\n", rc);
            sleep(1);
            mosquitto_reconnect(mosq);
        }
    }

    mosquitto_unsubscribe(mosq, NULL, argument->topic);
    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();
}

/**
 * @brief  gen_uuid
 * 产生uuid
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2021/2/6 13:56:29
 * @param  unsigned char *  uuid
 * @return static void
 */
static void gen_uuid(unsigned char *uuid)
{
    char buf[UUID4_LEN];

    int rc = uuid4_init();
    if (UUID4_ESUCCESS != rc) {
    }

    uuid4_generate(buf);
    char hex[33] = {'\0'};

    int n, m = 0;
    for (n = 0; n < 36; n++) {
        if ('-' == buf[n]) {
            continue;
        }

        hex[m] = buf[n];
        m++;
    }

    int i, j;
    for (i = 0, j = 0; j < 16; i += 2, j++) {
        uuid[j] = (unsigned char)((hex[i] % 32 + 9) % 25 * 16 + (hex[i + 1] % 32 + 9) % 25);
    }
}

/**
 * @brief  loop
 * 连接并循环发送交易
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2021/2/6 13:57:23
 * @param  LWSProtocol *    protocol
 * @return static void
 */
static void loop(LWSProtocol *protocol)
{
    // 等待mqtt连接完成
    while (1 != connected) {
        usleep(10 * 1000);
    }

    // 生成初始化请求
    sha256_hash hash;
    unsigned char listunspent_request[1024];
    size_t length = 0;
    LWSPError error = protocol_listunspent_request(protocol, hash, listunspent_request, &length);
    if (LWSPError_Success != error) {
        return;
    }

    // char hex[length * 2 + 1];
    // memset(hex, 0x00, length * 2 + 1);
    // sodium_bin2hex(hex, length * 2 + 1, listunspent_request, length);
    // printf("listunspent error:%d, length:%ld, hex:%s\n", error, length, hex);

    // 发送初始化请求
    int ret = message_sender(mosq, listunspent_request, length, hash);
    printf("connect message sender return:%d\n", ret);

    // 交易目标地址生成（本例发送到本地址）
    const char *target_hex = "e0b440ccdf4f2d014595e6fdec6e0cb38e18d08d2742ff777c012c4ea43ab588";
    unsigned char target[32];
    sodium_hex2bin(target, 32, target_hex, 64, NULL, NULL, NULL);
    protocol_utils_reverse(target, 32);

    sleep(2);
    for (;;) {
        // 生成交易载荷
        char *b64_json = "anNvbg==";
        TxVchData vch;
        unsigned char uuid[16];
        gen_uuid(vch.uuid);
        time_t now_time;
        time(&now_time);
        memcpy(vch.timestamp, &now_time, sizeof(now_time));
        vch.desc = b64_json;
        vch.desc_size = strlen(b64_json);
        char json[100] = {'\0'};
        sprintf(json, "{\"temperature\": %f}", (float)(rand() % 50 - 50));
        vch.len = strlen(json);
        vch.data = json;

        // 生成交易请求
        unsigned char sendtx_request[1024];
        length = 0;
        error = protocol_sendtx_request(protocol, target, &vch, hash, sendtx_request, &length);

        // 打印发送序列
        char hex[length * 2 + 1];
        memset(hex, 0x00, length * 2 + 1);
        sodium_bin2hex(hex, length * 2 + 1, sendtx_request, length);
        printf("sendtx error:%d, length:%ld, hex:%s\n", error, length, hex);

        // 同步发送交易请求
        int ret_sendtx = message_sender(mosq, sendtx_request, length, hash);
        printf("tx sender return:%d\n", ret_sendtx);

        // usleep(500 * 1000);
    }
}

/**
 * @brief  loop
 * 连接并循环发送交易
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2021/2/6 13:57:23
 * @param  LWSProtocol *    protocol
 * @return static void
 */
static void loop_1(LWSProtocol *protocol, unsigned char *target)
{
    // 等待mqtt连接完成
    while (1 != connected) {
        usleep(10 * 1000);
    }

    // 生成初始化请求
    sha256_hash hash;
    unsigned char listunspent_request[1024];
    size_t length = 0;
    LWSPError error = protocol_listunspent_request(protocol, hash, listunspent_request, &length);
    if (LWSPError_Success != error) {
        return;
    }

    // char hex[length * 2 + 1];
    // memset(hex, 0x00, length * 2 + 1);
    // sodium_bin2hex(hex, length * 2 + 1, listunspent_request, length);
    // printf("listunspent error:%d, length:%ld, hex:%s\n", error, length, hex);

    // 发送初始化请求
    int ret = message_sender(mosq, listunspent_request, length, hash);
    printf("connect message sender return:%d\n", ret);

    // 交易目标地址生成（本例发送到本地址）
    // const char *target_hex = "e0b440ccdf4f2d014595e6fdec6e0cb38e18d08d2742ff777c012c4ea43ab588";
    // unsigned char target[32];
    // sodium_hex2bin(target, 32, target_hex, 64, NULL, NULL, NULL);
    // protocol_utils_reverse(target, 32);

    sleep(2);
    for (;;) {
        // 生成交易载荷
        char *b64_json = "anNvbg==";
        TxVchData vch;
        unsigned char uuid[16];
        gen_uuid(vch.uuid);
        time_t now_time;
        time(&now_time);
        memcpy(vch.timestamp, &now_time, sizeof(now_time));
        vch.desc = b64_json;
        vch.desc_size = strlen(b64_json);
        char json[100] = {'\0'};
        sprintf(json, "{\"temperature\": %f}", (float)(rand() % 50 - 50));
        vch.len = strlen(json);
        vch.data = json;

        // 生成交易请求
        unsigned char sendtx_request[1024];
        length = 0;
        error = protocol_sendtx_request(protocol, target, &vch, hash, sendtx_request, &length);

        // 打印发送序列
        char hex[length * 2 + 1];
        memset(hex, 0x00, length * 2 + 1);
        sodium_bin2hex(hex, length * 2 + 1, sendtx_request, length);
        // printf("sendtx error:%d, length:%ld, hex:%s\n", error, length, hex);
        printf("sendtx error:%d, length:%ld\n", error, length);

        // 同步发送交易请求
        int ret_sendtx = message_sender(mosq, sendtx_request, length, hash);
        printf("tx sender return:%d\n", ret_sendtx);

        usleep(1000 * 1000);
    }
}

/// 字进程注册回调函数
static int hook_did_get_1(const void *context, unsigned char *id)
{
    memcpy(id, context, 12);

    return 12;
}

/// LWS Protocol 注册回调函数体

/**
 * @brief  hook_nonce_get
 * 随机数获取
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2021/2/6 13:49:6
 * @param  const void *     context
 * @return static unsigned int
 */
static unsigned int hook_nonce_get_1(const void *context) { return 101; }

/**
 * @brief  hook_datetime_get
 * 时间获取
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2021/2/6 13:49:24
 * @param  const void *     context
 * @return static unsigned int
 */
static unsigned int hook_datetime_get_1(const void *context)
{
    time_t now;
    time(&now);
    return now;
}

/**
 * @brief  hook_public_key_get
 * 目标公钥获取
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2021/2/6 13:50:23
 * @param  const void *     context
 * @param  ed25519_public_key  key
 * @return static int
 */
static int hook_public_key_get_1(const void *context, ed25519_public_key key)
{
    key[0] = 0x01; // 地址前缀
    memcpy(key + 1, context, 32);

    return 0;
}

/**
 * @brief  hook_fork_get
 * 交易分支id获取
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2021/2/6 13:51:8
 * @param  const void *     context
 * @param  big_num          fork
 * @return static int
 */
static int hook_fork_get_1(const void *context, big_num fork)
{
    memcpy(fork, context, 32);

    return 0;
}

/**
 * @brief  hook_sha256_get
 * SHA256 hash获取
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2021/2/6 13:51:50
 * @param  const void *     context
 * @param  const unsigned char * data
 * @param  size_t           len
 * @param  sha256_hash      hash
 * @return static int
 */
static int hook_sha256_get_1(const void *context, const unsigned char *data, size_t len, sha256_hash hash)
{
    return crypto_hash_sha256(hash, data, len);
}

/**
 * @brief  hook_crc32_get
 * crc32获取
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2021/2/6 13:53:0
 * @param  const void *     context
 * @param  const unsigned char * data
 * @param  const size_t     len
 * @return static unsigned int
 */
static unsigned int hook_crc32_get_1(const void *context, const unsigned char *data, const size_t len)
{
    return crc32(data, len);
}

/**
 * @brief  hook_sign_ed25519
 * ed25519 签名获取
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2021/2/6 13:53:45
 * @param  const void *     ctx
 * @param  const unsigned char * data
 * @param  const size_t     len
 * @param  ed25519_signature  signature
 * @return static int
 */
static int hook_sign_ed25519_1(const void *ctx, const unsigned char *data, const size_t len,
                               ed25519_signature signature)
{
    unsigned char key[64];
    unsigned char seed[64];
    memcpy(key, ctx, 32);
    crypto_sign_seed_keypair(&key[32], seed, (unsigned char *)key);

    unsigned char hash[32] = {0};
    crypto_generichash_blake2b(hash, sizeof(hash), data, len, NULL, 0);
    crypto_sign_ed25519_detached(signature, NULL, hash, sizeof(hash), key);

    return 0;
}

/**
 * @brief  hook_blake2b_get
 * blake2b hash获取
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2021/2/6 13:54:39
 * @param  const void *     ctx
 * @param  const unsigned char * data
 * @param  const size_t     len
 * @param  blake2b_hash     hash
 * @return static int
 */
static int hook_blake2b_get_1(const void *ctx, const unsigned char *data, const size_t len, blake2b_hash hash)
{
    crypto_generichash_blake2b(hash, 32, data, len, NULL, 0);
    return 0;
}

struct Arguments {
    int interval;
    char host[128];
    int port;
    unsigned char fork_id[32];
    unsigned char public_key[32];
    unsigned char private_key[32];
};

int child_func(struct Arguments arguments, int pfd0, int pfd1)
{
    LWSProtocolHook hook;

    // 设置device id回调函数
    char *topic = malloc(25);
    memset(topic, 0x00, 25);
    sodium_bin2hex(topic, 25, arguments.public_key, 12);

    unsigned char *did = malloc(32);
    memcpy(did, arguments.public_key, 32);
    hook.hook_id_context = did;
    hook.hook_id_get = hook_did_get_1;

    // 设置nonce回调函数
    hook.hook_nonce_get = hook_nonce_get_1;

    // 设置日期回调函数
    hook.hook_datetime_get = hook_datetime_get_1;

    // 设置获取公钥回调函数
    unsigned char *pk = malloc(32);
    memcpy(pk, arguments.public_key, 32);
    hook.hook_public_key_context = pk;
    hook.hook_public_key_get = hook_public_key_get_1;

    // 设置blake2b hash回调函数
    hook.hook_blake2b_get = hook_blake2b_get_1;

    // 设置获取fork id回调函数
    unsigned char *fid = malloc(32);
    memcpy(fid, arguments.fork_id, 32);
    hook.hook_fork_context = fid;
    hook.hook_fork_get = hook_fork_get_1;

    // 设置sha256 hash 回调函数
    hook.hook_sha256_get = hook_sha256_get_1;

    // 设置crc32回调函数
    hook.hook_crc32_get = hook_crc32_get_1;

    // 设置ed25519签名回调函数
    unsigned char *sk = malloc(32);
    memcpy(sk, arguments.private_key, 32);
    hook.hook_public_sign_ed25519_context = sk;
    hook.hook_public_sign_ed25519 = hook_sign_ed25519_1;

    // 初始化protocol实例
    LWSProtocol *protocol = NULL;
    LWSPError error = protocol_new(&hook, &protocol);
    if (LWSPError_Success != error) {
        printf("porotocol error:%d\n", error);
        return EXIT_FAILURE;
    }

    // 初始化发送端buffer
    memset(&buff, 0x00, sizeof(buff));
    pthread_mutex_init(&buff.lock, NULL);

    struct MqttThreadArgument *mqtt_argument = malloc(sizeof(struct MqttThreadArgument));
    mqtt_argument->protocol = protocol;
    memcpy(mqtt_argument->host, arguments.host, strlen(arguments.host));
    mqtt_argument->port = arguments.port;
    memcpy(mqtt_argument->topic, topic, strlen(topic));

    // 启动MQTT通讯进程
    pthread_t mqtt_thread_tid;
    int mqtt_thread_rc = pthread_create(&mqtt_thread_tid, NULL, (void *)mqtt_thread_1, mqtt_argument);
    if (0 != mqtt_thread_rc) {
        printf("create mqtt thread failure.\n");
        return EXIT_FAILURE;
    }

    // 产生&发送数据
    loop_1(protocol, arguments.public_key);

    // 删除协议实例
    if (NULL != protocol) {
        error = protocol_delete(protocol);
    }

    return 0;
}

int init_child_process(struct Arguments arguments)
{
    int pfd1[2], pfd2[2];
    if (0 > pipe(pfd1) || 0 > pipe(pfd2)) {
        // perror("pipe");
        exit(1);
    }

    pid_t pid;
    if ((pid = fork()) < 0) {
        /*error*/ /*TODO:syslog*/
        exit(1);
    } else if (0 == pid) {
        /*child*/
        close(pfd1[1]);
        close(pfd2[0]);

        child_func(arguments, pfd1[0], pfd2[1]);
        exit(0);
    } else {
        /*parent*/
        close(pfd1[0]);
        close(pfd2[1]);
    }

    return 0;
}

typedef int (*ReadLineCallback)(const void *ctx, char *line);

static int read_line_callback(const void *ctx, char *line)
{
    struct Arguments arguments;
    memcpy(&arguments, ctx, sizeof(struct Arguments));

    char *fork_id = strtok(line, ",");
    char *private_key = strtok(NULL, ",");
    char *public_key = strtok(NULL, ",");

    if (NULL == fork_id || NULL == private_key || NULL == public_key) {
        return -1;
    }

    unsigned char fid[32];
    protocol_utils_hex2bin(fork_id, 64, fid);
    memcpy(arguments.fork_id, fid, 32);

    unsigned char prikey[32];
    protocol_utils_hex2bin(private_key, 64, prikey);
    protocol_utils_reverse(prikey, 32); // 正常端序
    memcpy(arguments.private_key, prikey, 32);

    unsigned char pubkey[32];
    protocol_utils_hex2bin(public_key, 64, pubkey);
    protocol_utils_reverse(pubkey, 32); // 正常端序
    memcpy(arguments.public_key, pubkey, 32);

    init_child_process(arguments);

    return 0;
}

void read_line(FILE *f, struct Arguments arguments, ReadLineCallback cb)
{
    char line[1024] = {'\0'};

    char c;
    int len = 0;
    while ((c = fgetc(f)) != EOF && c != '\n') {
        line[len++] = c;
        line[len] = '\0';
    }

    cb(&arguments, line);
    return;
}

int main(int argc, char **argv)
{
    struct option long_options[] = {
        {"file", required_argument, NULL, 'f'},     {"count", required_argument, NULL, 'c'},
        {"interval", required_argument, NULL, 'i'}, {"host", required_argument, NULL, 'h'},
        {"port", required_argument, NULL, 'p'},     {0, 0, 0, 0},
    };

    char file_path[PATH_MAX + 1] = {'\0'};
    int proccess_count = 0;
    int interval = 0;
    char host[128] = {'\0'};
    int port = 1883;

    int option_index = 0;
    int c = 0;
    while ((c = getopt_long(argc, argv, "f:c:i:h:p:", long_options, &option_index)) != -1) {
        switch (c) {
            case 'f':
                strncpy(file_path, optarg, sizeof(file_path) - 1);
                break;
            case 'c':
                proccess_count = atoi(optarg);
                break;
            case 'i':
                interval = atoi(optarg);
                break;
            case 'h':
                strncpy(host, optarg, sizeof(host) - 1);
                break;
            case 'p':
                port = atoi(optarg);
                break;
            default:
                break;
        }
    }

    printf("File path:%s, Proccess count:%d, Interval:%d\n", file_path, proccess_count, interval);
    printf("Host:%s, Port:%d\n", host, port);

    if (0 == strlen(file_path)) {
        return EXIT_FAILURE;
    }

    struct Arguments arguments;
    memset(&arguments, 0x00, sizeof(arguments));
    arguments.interval = interval;
    strcpy(arguments.host, host);
    arguments.port = port;

    FILE *csv_fd = fopen(file_path, "r");
    char line[1024] = {'\0'};

    for (int i = 0; i < proccess_count; i++) {
        read_line(csv_fd, arguments, read_line_callback);
    }
    fclose(csv_fd);

    // // 注册回调函数
    // LWSProtocolHook hook;
    // hook.hook_id_get = hook_did_get;
    // hook.hook_nonce_get = hook_nonce_get;
    // hook.hook_datetime_get = hook_datetime_get;
    // hook.hook_public_key_get = hook_public_key_get;
    // hook.hook_blake2b_get = hook_blake2b_get;
    // hook.hook_fork_get = hook_fork_get;
    // hook.hook_sha256_get = hook_sha256_get;
    // hook.hook_crc32_get = hook_crc32_get;
    // hook.hook_public_sign_ed25519 = hook_sign_ed25519;

    // // 初始化protocol实例
    // LWSProtocol *protocol = NULL;
    // LWSPError error = protocol_new(&hook, &protocol);
    // if (LWSPError_Success != error) {
    //     printf("porotocol error:%d\n", error);
    //     return EXIT_FAILURE;
    // }

    // // 初始化发送端buffer
    // memset(&buff, 0x00, sizeof(buff));
    // pthread_mutex_init(&buff.lock, NULL);

    // // 启动MQTT通讯进程
    // pthread_t mqtt_thread_tid;
    // int mqtt_thread_rc = pthread_create(&mqtt_thread_tid, NULL, (void *)mqtt_thread, protocol);
    // if (0 != mqtt_thread_rc) {
    //     printf("create mqtt thread failure.\n");
    //     return EXIT_FAILURE;
    // }

    // // 产生&发送数据
    // loop(protocol);

    // // 删除协议实例
    // if (NULL != protocol) {
    //     error = protocol_delete(protocol);
    // }

    for (;;) {
        sleep(1);
    }

    return EXIT_SUCCESS;
}