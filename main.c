#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sodium.h>
#include <mosquitto.h>
#include "crc32.h"
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
    for (i = 0; i < 1000; i++) {
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

    if (ListUnspent == info.command) {
        error = protocol_listunspent_reply_handle(protocol, data, length);
    }

    if (SendTx == info.command) {
    }
    pthread_mutex_unlock(&buff.lock);

    return 0;
}

static void connect_callback(struct mosquitto *mosq, void *obj, int result)
{
    LWSProtocol *protocol = (LWSProtocol *)obj;
    printf("connect callback, rc=%d\n", result);

    connected = 1;
}

static void message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
    LWSProtocol *protocol = (LWSProtocol *)obj;
    // receiver
    char hex[message->payloadlen * 2 + 1];
    memset(hex, 0x00, message->payloadlen * 2 + 1);
    sodium_bin2hex(hex, message->payloadlen * 2 + 1, message->payload, message->payloadlen);

    printf("got message '%.*s' for topic '%s'\n", message->payloadlen * 2 + 1, hex, message->topic);
    int rc = message_receiver(protocol, message->payload, message->payloadlen);
    printf("message_callback return:%d\n", rc);
}

static void publish_callback(struct mosquitto *mosq, void *data, int mid) {}

static int hook_did_get(const void *context, unsigned char *id)
{
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

    char *host = "192.168.199.228";
    int port = 1883;
    mosquitto_connect_callback_set(mosq, connect_callback);
    mosquitto_message_callback_set(mosq, message_callback);
    mosquitto_publish_callback_set(mosq, publish_callback);

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

static void loop(LWSProtocol *protocol)
{
    while (1 != connected) {
        usleep(10 * 1000);
    }

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

    // sender
    int ret = message_sender(mosq, listunspent_request, length, hash);
    printf("connect message sender return:%d\n", ret);

    for (;;) {
        sleep(1);
    }
}

int main(int argc, char **argv)
{
    // 初始化protocol
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
    if (LWSPError_Success != error) {
        printf("porotocol error:%d\n", error);
        return EXIT_FAILURE;
    }

    // 初始化发送端buffer
    memset(&buff, 0x00, sizeof(buff));
    pthread_mutex_init(&buff.lock, NULL);

    // 启动MQTT通讯进程
    pthread_t mqtt_thread_tid;
    int mqtt_thread_rc = pthread_create(&mqtt_thread_tid, NULL, (void *)mqtt_thread, protocol);
    if (0 != mqtt_thread_rc) {
        printf("create mqtt thread failure.\n");
        return EXIT_FAILURE;
    }

    // 产生&发送数据
    loop(protocol);

    if (NULL != protocol) {
        error = protocol_delete(protocol);
    }

    return EXIT_SUCCESS;
}