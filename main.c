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
    printf("message_sender hash:%s\n", hex);

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

    printf("got message '%.*s' for topic '%s'\n", message->payloadlen * 2 + 1, hex, message->topic);
    int rc = message_receiver(protocol, message->payload, message->payloadlen);
    printf("message_callback return:%d\n", rc);
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
static void loop_1(LWSProtocol *protocol)
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

/// Base32

// clang-format off
static const unsigned int crc24q_table[256] = {
    0x00000000, 0x01864CFB, 0x028AD50D, 0x030C99F6, 0x0493E6E1, 0x0515AA1A, 0x061933EC, 0x079F7F17, 0x08A18139,
    0x0927CDC2, 0x0A2B5434, 0x0BAD18CF, 0x0C3267D8, 0x0DB42B23, 0x0EB8B2D5, 0x0F3EFE2E, 0x10C54E89, 0x11430272,
    0x124F9B84, 0x13C9D77F, 0x1456A868, 0x15D0E493, 0x16DC7D65, 0x175A319E, 0x1864CFB0, 0x19E2834B, 0x1AEE1ABD,
    0x1B685646, 0x1CF72951, 0x1D7165AA, 0x1E7DFC5C, 0x1FFBB0A7, 0x200CD1E9, 0x218A9D12, 0x228604E4, 0x2300481F,
    0x249F3708, 0x25197BF3, 0x2615E205, 0x2793AEFE, 0x28AD50D0, 0x292B1C2B, 0x2A2785DD, 0x2BA1C926, 0x2C3EB631,
    0x2DB8FACA, 0x2EB4633C, 0x2F322FC7, 0x30C99F60, 0x314FD39B, 0x32434A6D, 0x33C50696, 0x345A7981, 0x35DC357A,
    0x36D0AC8C, 0x3756E077, 0x38681E59, 0x39EE52A2, 0x3AE2CB54, 0x3B6487AF, 0x3CFBF8B8, 0x3D7DB443, 0x3E712DB5,
    0x3FF7614E, 0x4019A3D2, 0x419FEF29, 0x429376DF, 0x43153A24, 0x448A4533, 0x450C09C8, 0x4600903E, 0x4786DCC5,
    0x48B822EB, 0x493E6E10, 0x4A32F7E6, 0x4BB4BB1D, 0x4C2BC40A, 0x4DAD88F1, 0x4EA11107, 0x4F275DFC, 0x50DCED5B,
    0x515AA1A0, 0x52563856, 0x53D074AD, 0x544F0BBA, 0x55C94741, 0x56C5DEB7, 0x5743924C, 0x587D6C62, 0x59FB2099,
    0x5AF7B96F, 0x5B71F594, 0x5CEE8A83, 0x5D68C678, 0x5E645F8E, 0x5FE21375, 0x6015723B, 0x61933EC0, 0x629FA736,
    0x6319EBCD, 0x648694DA, 0x6500D821, 0x660C41D7, 0x678A0D2C, 0x68B4F302, 0x6932BFF9, 0x6A3E260F, 0x6BB86AF4,
    0x6C2715E3, 0x6DA15918, 0x6EADC0EE, 0x6F2B8C15, 0x70D03CB2, 0x71567049, 0x725AE9BF, 0x73DCA544, 0x7443DA53,
    0x75C596A8, 0x76C90F5E, 0x774F43A5, 0x7871BD8B, 0x79F7F170, 0x7AFB6886, 0x7B7D247D, 0x7CE25B6A, 0x7D641791,
    0x7E688E67, 0x7FEEC29C, 0x803347A4, 0x81B50B5F, 0x82B992A9, 0x833FDE52, 0x84A0A145, 0x8526EDBE, 0x862A7448,
    0x87AC38B3, 0x8892C69D, 0x89148A66, 0x8A181390, 0x8B9E5F6B, 0x8C01207C, 0x8D876C87, 0x8E8BF571, 0x8F0DB98A,
    0x90F6092D, 0x917045D6, 0x927CDC20, 0x93FA90DB, 0x9465EFCC, 0x95E3A337, 0x96EF3AC1, 0x9769763A, 0x98578814,
    0x99D1C4EF, 0x9ADD5D19, 0x9B5B11E2, 0x9CC46EF5, 0x9D42220E, 0x9E4EBBF8, 0x9FC8F703, 0xA03F964D, 0xA1B9DAB6,
    0xA2B54340, 0xA3330FBB, 0xA4AC70AC, 0xA52A3C57, 0xA626A5A1, 0xA7A0E95A, 0xA89E1774, 0xA9185B8F, 0xAA14C279,
    0xAB928E82, 0xAC0DF195, 0xAD8BBD6E, 0xAE872498, 0xAF016863, 0xB0FAD8C4, 0xB17C943F, 0xB2700DC9, 0xB3F64132,
    0xB4693E25, 0xB5EF72DE, 0xB6E3EB28, 0xB765A7D3, 0xB85B59FD, 0xB9DD1506, 0xBAD18CF0, 0xBB57C00B, 0xBCC8BF1C,
    0xBD4EF3E7, 0xBE426A11, 0xBFC426EA, 0xC02AE476, 0xC1ACA88D, 0xC2A0317B, 0xC3267D80, 0xC4B90297, 0xC53F4E6C,
    0xC633D79A, 0xC7B59B61, 0xC88B654F, 0xC90D29B4, 0xCA01B042, 0xCB87FCB9, 0xCC1883AE, 0xCD9ECF55, 0xCE9256A3,
    0xCF141A58, 0xD0EFAAFF, 0xD169E604, 0xD2657FF2, 0xD3E33309, 0xD47C4C1E, 0xD5FA00E5, 0xD6F69913, 0xD770D5E8,
    0xD84E2BC6, 0xD9C8673D, 0xDAC4FECB, 0xDB42B230, 0xDCDDCD27, 0xDD5B81DC, 0xDE57182A, 0xDFD154D1, 0xE026359F,
    0xE1A07964, 0xE2ACE092, 0xE32AAC69, 0xE4B5D37E, 0xE5339F85, 0xE63F0673, 0xE7B94A88, 0xE887B4A6, 0xE901F85D,
    0xEA0D61AB, 0xEB8B2D50, 0xEC145247, 0xED921EBC, 0xEE9E874A, 0xEF18CBB1, 0xF0E37B16, 0xF16537ED, 0xF269AE1B,
    0xF3EFE2E0, 0xF4709DF7, 0xF5F6D10C, 0xF6FA48FA, 0xF77C0401, 0xF842FA2F, 0xF9C4B6D4, 0xFAC82F22, 0xFB4E63D9,
    0xFCD11CCE, 0xFD575035, 0xFE5BC9C3, 0xFFDD8538,
};

// clang-format on

static unsigned int crc24q(const unsigned char *data, int size)
{
    unsigned int crc = 0;
    for (int i = 0; i < size; i++) {
        crc = (crc << 8) ^ crc24q_table[data[i] ^ (0xFF & (crc >> 16))];
    }

    crc = (crc & 0x00ffffff);

    return crc;
}

static void crypto_base32_encode_5bytes(const unsigned char *md5, char *str_base32)
{
    static const char *alphabet = "0123456789abcdefghjkmnpqrstvwxyz";

    str_base32[0] = alphabet[(md5[0] >> 3) & 0x1F];
    str_base32[1] = alphabet[((md5[0] << 2) & 0x1C) | ((md5[1] >> 6) & 0x03)];
    str_base32[2] = alphabet[(md5[1] >> 1) & 0x1F];
    str_base32[3] = alphabet[((md5[1] << 4) & 0x10) | ((md5[2] >> 4) & 0x0F)];
    str_base32[4] = alphabet[((md5[2] << 1) & 0x1E) | ((md5[3] >> 7) & 0x01)];
    str_base32[5] = alphabet[(md5[3] >> 2) & 0x1F];
    str_base32[6] = alphabet[((md5[3] << 3) & 0x18) | ((md5[4] >> 5) & 0x07)];
    str_base32[7] = alphabet[(md5[4] & 0x1F)];
}

void crypto_base32_encode(const unsigned char *md32, char *out)
{
    unsigned int crc = crc24q(md32, 32);
    int i;
    for (i = 0; i < 30; i += 5) {
        int index = i / 5;
        crypto_base32_encode_5bytes(md32 + i, out + (index * 8));
    }
    unsigned char tail[5] = {md32[30], md32[31], (unsigned char)(crc >> 16), (unsigned char)(crc >> 8),
                             (unsigned char)crc};
    crypto_base32_encode_5bytes(tail, out + (6 * 8));
}

static int base32_decode_5bytes(const char *psz, unsigned char *md5)
{
    // clang-format off
    static const char digit[256] = { 
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0,
        1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, 16, 17, -1, 18, 19, -1, 20, 21,
        -1, 22, 23, 24, 25, 26, -1, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, 16, 17, -1, 18,
        19, -1, 20, 21, -1, 22, 23, 24, 25, 26, -1, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1 
    };
    // clang-format on

    char idx[8];
    int sum = 0;
    sum &= (idx[0] = digit[(int)*psz++]);
    sum &= (idx[1] = digit[(int)*psz++]);
    sum &= (idx[2] = digit[(int)*psz++]);
    sum &= (idx[3] = digit[(int)*psz++]);
    sum &= (idx[4] = digit[(int)*psz++]);
    sum &= (idx[5] = digit[(int)*psz++]);
    sum &= (idx[6] = digit[(int)*psz++]);
    sum &= (idx[7] = digit[(int)*psz++]);

    md5[0] = ((idx[0] << 3) & 0xF8) | ((idx[1] >> 2) & 0x07);
    md5[1] = ((idx[1] << 6) & 0xC0) | ((idx[2] << 1) & 0x3E) | ((idx[3] >> 4) & 0x01);
    md5[2] = ((idx[3] << 4) & 0xF0) | ((idx[4] >> 1) & 0x0F);
    md5[3] = ((idx[4] << 7) & 0x80) | ((idx[5] << 2) & 0x7C) | ((idx[6] >> 3) & 0x03);
    md5[4] = ((idx[6] << 5) & 0xE0) | ((idx[7] & 0x1F));

    return (!(sum >> 7));
}

int crypto_base32_decode(const char *in, unsigned char *md32)
{
    unsigned char data[35];

    for (int i = 0; i < 7; i++) {
        if (!base32_decode_5bytes(in + (i * 8), data + i * 5)) {
            return -1;
        }
    }

    if (crc24q(data, 35) != 0) {
        return -1;
    }

    memmove(md32, data, 32);
    return 0;
}

/// 字进程注册回调函数

static int hook_did_get_1(const void *context, unsigned char *id)
{
    memcpy(id, context, 57);

    return 57;
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
    memcpy(key, context, 32);

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
static int hook_blake2b_get_1(const void *ctx, const unsigned char *data, const size_t len, blake2b_hash hash)
{
    crypto_generichash_blake2b(hash, 32, data, len, NULL, 0);
    return 0;
}

struct Arguments {
    int interval;
    char host[128];
    int port;
    unsigned char fork_id[64];
    unsigned char public_key[64];
    unsigned char private_key[64];
};

int child_func(struct Arguments arguments, int pfd0, int pfd1)
{
    LWSProtocolHook hook;

    // 设置device id回调函数
    char *address = malloc(58);
    address[0] = '1';
    crypto_base32_encode(arguments.public_key, address + 1);
    hook.hook_id_context = address;
    printf("address:%s\n", (char *)hook.hook_id_context);
    hook.hook_id_get = hook_did_get_1;

    // 设置nonce回调函数
    hook.hook_nonce_get = hook_nonce_get_1;

    // 设置日期回调函数
    hook.hook_datetime_get = hook_datetime_get_1;

    // 设置获取公钥回调函数
    unsigned char *pk = malloc(64);
    memcpy(pk, arguments.public_key, 64);
    hook.hook_public_key_context = pk;
    hook.hook_public_key_get = hook_public_key_get_1;

    // 设置blake2b hash回调函数
    hook.hook_blake2b_get = hook_blake2b_get_1;

    // 设置获取fork id回调函数
    unsigned char *new_fid = malloc(64);
    memcpy(new_fid, arguments.fork_id, 64);
    hook.hook_fork_context = new_fid;
    hook.hook_fork_get = hook_fork_get_1;

    // 设置sha256 hash 回调函数
    hook.hook_sha256_get = hook_sha256_get_1;

    // 设置crc32回调函数
    hook.hook_crc32_get = hook_crc32_get_1;

    // 设置ed25519签名回调函数
    unsigned char *sk = malloc(64);
    memcpy(sk, arguments.private_key, 64);
    hook.hook_public_sign_ed25519_context = sk;
    hook.hook_public_sign_ed25519 = hook_sign_ed25519_1;

    return 0;

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

    // 启动MQTT通讯进程
    pthread_t mqtt_thread_tid;
    int mqtt_thread_rc = pthread_create(&mqtt_thread_tid, NULL, (void *)mqtt_thread_1, mqtt_argument);
    if (0 != mqtt_thread_rc) {
        printf("create mqtt thread failure.\n");
        return EXIT_FAILURE;
    }

    // 产生&发送数据
    loop_1(protocol);

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
    protocol_utils_reverse(fid, 32); // 正常端序
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
    int proccess_count = 1;
    int interval = 0;
    char host[128] = {'\0'};
    int port = 1883;

    int option_index = 0;
    int c = 0;
    while ((c = getopt_long(argc, argv, "f:c:i:h:i:", long_options, &option_index)) != -1) {
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

    return EXIT_SUCCESS;
}