#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sodium.h>
#include "lws_protocol.h"

// ArrayList used c-algorithms--https://fragglet.github.io/c-algorithms/doc/arraylist_8h.html

typedef void *ArrayListValue;
typedef struct _ArrayList ArrayList;

struct _ArrayList {
    ArrayListValue *data;
    unsigned int length;
    unsigned int _alloced;
};

typedef int (*ArrayListEqualFunc)(ArrayListValue value1, ArrayListValue value2);
typedef int (*ArrayListCompareFunc)(ArrayListValue value1, ArrayListValue value2);

static ArrayList *arraylist_new(unsigned int length)
{
    ArrayList *new_arraylist;

    if (length <= 0) {
        length = 16;
    }

    new_arraylist = (ArrayList *)malloc(sizeof(ArrayList));

    if (new_arraylist == NULL) {
        return NULL;
    }

    new_arraylist->_alloced = length;
    new_arraylist->length = 0;

    new_arraylist->data = malloc(length * sizeof(ArrayListValue));

    if (new_arraylist->data == NULL) {
        free(new_arraylist);
        return NULL;
    }

    return new_arraylist;
}

static void arraylist_free(ArrayList *arraylist)
{
    if (arraylist != NULL) {
        free(arraylist->data);
        free(arraylist);
    }
}

static int arraylist_enlarge(ArrayList *arraylist)
{
    ArrayListValue *data;
    unsigned int newsize;

    newsize = arraylist->_alloced * 2;

    data = realloc(arraylist->data, sizeof(ArrayListValue) * newsize);

    if (data == NULL) {
        return 0;
    } else {
        arraylist->data = data;
        arraylist->_alloced = newsize;

        return 1;
    }
}

static int arraylist_insert(ArrayList *arraylist, unsigned int index, ArrayListValue data)
{
    if (index > arraylist->length) {
        return 0;
    }

    if (arraylist->length + 1 > arraylist->_alloced) {
        if (!arraylist_enlarge(arraylist)) {
            return 0;
        }
    }

    memmove(&arraylist->data[index + 1], &arraylist->data[index], (arraylist->length - index) * sizeof(ArrayListValue));

    arraylist->data[index] = data;
    ++arraylist->length;

    return 1;
}

static int arraylist_append(ArrayList *arraylist, ArrayListValue data)
{
    return arraylist_insert(arraylist, arraylist->length, data);
}

// static int arraylist_prepend(ArrayList *arraylist, ArrayListValue data) { return arraylist_insert(arraylist, 0,
// data); }

static void arraylist_remove_range(ArrayList *arraylist, unsigned int index, unsigned int length)
{
    if (index > arraylist->length || index + length > arraylist->length) {
        return;
    }

    memmove(&arraylist->data[index], &arraylist->data[index + length],
            (arraylist->length - (index + length)) * sizeof(ArrayListValue));

    arraylist->length -= length;
}

static void arraylist_remove(ArrayList *arraylist, unsigned int index) { arraylist_remove_range(arraylist, index, 1); }

static int arraylist_index_of(ArrayList *arraylist, ArrayListEqualFunc callback, ArrayListValue data)
{
    unsigned int i;

    for (i = 0; i < arraylist->length; ++i) {
        if (callback(arraylist->data[i], data) != 0)
            return (int)i;
    }

    return -1;
}

static void arraylist_clear(ArrayList *arraylist) { arraylist->length = 0; }

static void arraylist_sort_internal(ArrayListValue *list_data, unsigned int list_length,
                                    ArrayListCompareFunc compare_func)
{
    ArrayListValue pivot;
    ArrayListValue tmp;
    unsigned int i;
    unsigned int list1_length;
    unsigned int list2_length;

    if (list_length <= 1) {
        return;
    }

    pivot = list_data[list_length - 1];

    list1_length = 0;

    for (i = 0; i < list_length - 1; ++i) {

        if (compare_func(list_data[i], pivot) < 0) {
            tmp = list_data[i];
            list_data[i] = list_data[list1_length];
            list_data[list1_length] = tmp;

            ++list1_length;

        } else {
        }
    }

    list2_length = list_length - list1_length - 1;

    list_data[list_length - 1] = list_data[list1_length];
    list_data[list1_length] = pivot;

    arraylist_sort_internal(list_data, list1_length, compare_func);

    arraylist_sort_internal(&list_data[list1_length + 1], list2_length, compare_func);
}

static void arraylist_sort(ArrayList *arraylist, ArrayListCompareFunc compare_func)
{
    arraylist_sort_internal(arraylist->data, arraylist->length, compare_func);
}

typedef struct {
    uint16_t version;
    uint16_t type;
    uint32_t timestamp;
    uint32_t lock_until;
    unsigned char hash_anchor[32];
    uint8_t size0;
    unsigned char *input;
    uint8_t prefix;
    unsigned char address[32];
    uint64_t amount;
    uint64_t tx_fee;
    uint8_t size1;
    unsigned char *vch_data;
    uint8_t size2;
    unsigned char sign[64];
} Transaction;

struct _LWSProtocol {
    uint32_t listunspent_index;
    uint32_t sendtx_index;
    LWSProtocolHook *hook;
    ArrayList *utxo_list;
    unsigned char last_block_hash[32];
    uint32_t last_block_height;
    uint32_t last_block_time;
    uint32_t next_amount;
};

struct ListUnspentRequest {
    uint32_t nonce;
    unsigned char address[33];
    unsigned char fork_id[32];
};

struct SendTxRequest {
    uint32_t nonce;
    unsigned char tx_id[32];
    unsigned char fork_id[32];
    uint16_t data_size;
    unsigned char *tx_data;
};

struct UTXO {
    unsigned char txid[32];
    uint8_t out;
    uint32_t timestamp;
    uint16_t type;
    uint32_t amount;
    unsigned char sender[33];
    uint32_t lock_until;
    uint16_t data_size;
    unsigned char *data;
};

struct ListUnspentBody {
    uint16_t command;
    uint32_t nonce;
    unsigned char block_hash[32];
    uint32_t block_height;
    uint32_t block_time;
    uint16_t utxo_number;
    ArrayList *utxo_list;
};

struct SendTxBody {
    uint16_t command;
    uint32_t nonce;
    unsigned char tx_id[32];
};

struct RequestHead {
    uint16_t version;
    uint8_t length;
    unsigned char *id;
    unsigned char hash[32];
};

/**
 * @brief  hex2char
 * Convert hex to unsigned char array(bytes)
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2019/11/18 17:0:47
 * @param  char *           hex -input hex string
 * @param  unsigned char *  bin -output unsigned char array
 * @return static size_t
 */
static size_t hex_to_uchar(const char *hex, unsigned char *bin)
{
    size_t len = strlen(hex);
    size_t final_len = len / 2;
    size_t i, j;
    for (i = 0, j = 0; j < final_len; i += 2, j++) {
        bin[j] = (unsigned char)((hex[i] % 32 + 9) % 25 * 16 + (hex[i + 1] % 32 + 9) % 25);
    }

    return final_len;
}

/**
 * @brief  reverse
 * reverse the unisgned char array
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2020/9/11 11:8:51
 * @param  unsigned char *  p
 * @param  int              size
 * @return  void
 */
static void reverse(unsigned char *p, int size)
{
    int i;
    unsigned char tmp;
    for (i = 0; i < size / 2; i++) {
        tmp = p[i];
        p[i] = p[size - 1 - i];
        p[size - 1 - i] = tmp;
    }
}

static int big_num_compare(big_num data1, big_num data2)
{
    int i;
    for (i = 31; i >= 0; i--) {
        // printf("%d, data1:%u, data2:%u\n", i, data1->pn[i], data2->pn[i]);
        if (data1[i] > data2[i]) {
            return 1;
        }

        if (data1[i] == data2[i]) {
            continue;
        }

        if (data1[i] < data2[i]) {
            return -1;
        }
    }

    return 0;
}

/**
 * @brief  serialize_join
 * serialize unsigned char array
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2019/8/7 17:4:50
 * @param  size_t *         size -i/o array len，first call set to zero
 * @param  void *           thing -void ptr for something that need to be serialized
 * @param  size_t           size_thing -length of things that need to be serialized(byte size)
 * @param  unsigned char *  data -output series
 * @return static size_t -size
 */
static size_t serialize_join(size_t *size, void *thing, size_t size_thing, unsigned char *data)
{
    memcpy(data + *size, thing, size_thing);
    *size += size_thing;
    return *size;
}

/**
 * @brief  deserialize_join
 * Deserialize to struct case
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2019/8/19 21:20:28
 * @param  size_t *         size -byte length counter
 * @param  unsigned char *  data -data series
 * @param  void *           thing -struct case ptr
 * @param  size_t           size_thing -something that need tobe deserialized
 * @return static size_t -size
 */
static size_t deserialize_join(size_t *size, const unsigned char *data, void *thing, size_t size_thing)
{
    memcpy(thing, data + *size, size_thing);
    *size += size_thing;

    return *size;
}

size_t protocol_utils_hex2bin(const char *hex, unsigned char *bin) { return hex_to_uchar(hex, bin); }

void protocol_utils_reverse(void *data, size_t size) { return reverse((unsigned char *)data, size); }

/**
 * @brief  protocol_new
 * create new protocol object
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2021/1/26 22:22:0
 * @param  const LWSProtocolHook * hook
 * @param  LWSProtocol **   protocol
 * @return  LWSPError
 */
LWSPError protocol_new(const LWSProtocolHook *hook, LWSProtocol **protocol)
{
    if (NULL == hook) {
        return LWSPError_Hook_NULL;
    }

    if (NULL == hook->hook_id_get) {
        return LWSPError_HookDevieIDGet_NULL;
    }

    if (NULL == hook->hook_nonce_get) {
        return LWSPError_HookNonceGet_NULL;
    }

    if (NULL == hook->hook_datetime_get) {
        return LWSPError_HookDatetimeGet_NULL;
    }

    if (NULL == hook->hook_public_key_get) {
        return LWSPError_HookPublicKeyGet_NULL;
    }

    if (NULL == hook->hook_fork_get) {
        return LWSPError_HookForkGet_NULL;
    }

    if (NULL == hook->hook_sha256_get) {
        return LWSPError_HookSHA256GET_NULL;
    }

    unsigned char id[256];
    int id_length = hook->hook_id_get(hook->hook_id_context, id);
    if (256 < id_length || 0 == id_length) {
        return LWSPError_ID_Length;
    }

    *protocol = malloc(sizeof(LWSProtocol));
    if (NULL == *protocol) {
        return LWSPError_Allocate_Fail;
    }

    memset(*protocol, 0x00, sizeof(LWSProtocol));
    (*protocol)->hook = malloc(sizeof(LWSProtocolHook));
    if (NULL == (*protocol)->hook) {
        free(*protocol);
        *protocol = NULL;
        return LWSPError_Allocate_Fail;
    }

    memcpy((*protocol)->hook, hook, sizeof(LWSProtocolHook));
    (*protocol)->listunspent_index = 0;
    (*protocol)->sendtx_index = 0;
    (*protocol)->utxo_list = arraylist_new(0);

    return LWSPError_Success;
}

static int check_endian()
{
    int a = 1;
    char *p = (char *)&a;

    return (*p == 1); /*1:little-endian, 0:big-endian*/
}

static LWSPError wrap_request(LWSProtocol *protocol, const unsigned char *data, const size_t data_len, sha256_hash hash,
                              unsigned char *request, size_t *length)
{
    struct RequestHead head;
    head.version = VERSION;
    unsigned char device_id[256];
    head.length = protocol->hook->hook_id_get(protocol->hook->hook_id_context, device_id);
    head.id = device_id;
    memcpy(head.hash, hash, 32);
    uint32_t foot = 0;

    size_t len = 2 + 1 + head.length + 32 + data_len + 4;
    memcpy(request, &head.version, 2);
    memcpy(&request[2], &head.length, 1);
    memcpy(&request[3], head.id, head.length);
    memcpy(&request[3 + head.length], hash, 32);
    memcpy(&request[3 + head.length + 32], data, data_len);

    foot = protocol->hook->hook_crc32_get(protocol->hook->hook_crc32_context, request, len - 4);
    memcpy(&request[3 + head.length + 32 + data_len], &foot, 4);
    *length = len;

    return LWSPError_Success;
}

LWSPError protocol_listunspent_request(LWSProtocol *protocol, sha256_hash hash, unsigned char *data, size_t *length)
{
    if (NULL == protocol) {
        return LWSPError_Protocol_NULL;
    }

    if (NULL == protocol->hook) {
        return LWSPError_Hook_NULL;
    }

    struct ListUnspentRequest request;
    request.nonce = protocol->hook->hook_nonce_get(protocol->hook->hook_nonce_context);
    protocol->hook->hook_public_key_get(protocol->hook->hook_public_key_context, request.address);
    protocol->hook->hook_fork_get(protocol->hook->hook_fork_context, request.fork_id);

    size_t body_len = 4 + 33 + 32 + 2;
    unsigned char body[body_len];
    uint16_t command = ListUnspent;
    memcpy(body, &command, 2);
    memcpy(&body[2], &request, body_len - 2);
    protocol->hook->hook_sha256_get(protocol->hook->hook_sha256_context, body, body_len, hash);

    wrap_request(protocol, body, body_len, hash, data, length);
    protocol->listunspent_index++;

    return LWSPError_Success;
}

/**
 * @brief  compare_utxo
 * Compare v1(UTXO) and v2(UTXO)
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2019/11/18 17:50:58
 * @param  ArrayListValue   v1 -input UTXO instance
 * @param  ArrayListValue   v2 -input UTXO instance
 * @return static int --if equal return 0, v1 greater then v2 return 1, else return -1
 */
static int compare_utxo(ArrayListValue v1, ArrayListValue v2)
{
    struct UTXO *utxo1 = (struct UTXO *)v1;
    struct UTXO *utxo2 = (struct UTXO *)v2;

    big_num txid1, txid2;
    memcpy(txid1, utxo1->txid, 32);
    memcpy(txid2, utxo2->txid, 32);

    int ret = big_num_compare(txid1, txid2);

    // sort rule--ArrayListCompareFunc
    // https://fragglet.github.io/c-algorithms/doc/arraylist_8h.html

    // utxo == utxo2
    if (0 == ret) {
        if (utxo1->out == utxo2->out) {
            return 0;
        }

        if (utxo1->out > utxo2->out) {
            return 1;
        }

        if (utxo1->out < utxo2->out) {
            return -1;
        }
    }

    // utxo1 > utxo2
    if (1 == ret) {
        return 1;
    }

    // utxo1 < utxo2
    if (-1 == ret) {
        return -1;
    }

    return -1;
}

static LWSPError reply_remove_head(const unsigned char *data, const size_t length, unsigned char *body,
                                   size_t *body_len)
{
    if (36 > length) {
        return LWSPError_Reply_Too_Short; // 数据长度错误
    }

    if ((length - 36) > 0) {
        memcpy(body, &data[36], length - 36);
        *body_len = length - 36;
    } else {
        return LWSPError_Empty_Command_Body;
    }

    return LWSPError_Success;
}

static struct ListUnspentBody listunspent_body_deserialize(const unsigned char *data)
{
    struct ListUnspentBody body;
    body.utxo_list = arraylist_new(0);
    size_t size = 0;
    size_t size_thing = sizeof(body.command);
    deserialize_join(&size, data, &body.command, size_thing);

    size_thing = sizeof(body.nonce);
    deserialize_join(&size, data, &body.nonce, size_thing);

    size_thing = sizeof(body.block_hash);
    deserialize_join(&size, data, body.block_hash, size_thing);

    size_thing = sizeof(body.block_height);
    deserialize_join(&size, data, &body.block_height, size_thing);

    size_thing = sizeof(body.block_time);
    deserialize_join(&size, data, &body.block_time, size_thing);

    size_thing = sizeof(body.utxo_number);
    deserialize_join(&size, data, &body.utxo_number, size_thing);

    // 端序转换
    reverse((unsigned char *)&body.command, 2);
    reverse((unsigned char *)&body.nonce, 4);
    reverse((unsigned char *)&body.block_height, 4);
    reverse((unsigned char *)&body.block_time, 4);
    reverse((unsigned char *)&body.utxo_number, 2);

    // UTXOList
    int i;
    for (i = 0; i < body.utxo_number; i++) {
        struct UTXO *utxo = (struct UTXO *)malloc(sizeof(struct UTXO));

        size_thing = sizeof(utxo->txid);
        deserialize_join(&size, data, utxo->txid, size_thing);

        size_thing = sizeof(utxo->out);
        deserialize_join(&size, data, &utxo->out, size_thing);

        size_thing = sizeof(utxo->timestamp);
        deserialize_join(&size, data, &utxo->timestamp, size_thing);

        size_thing = sizeof(utxo->type);
        deserialize_join(&size, data, &utxo->type, size_thing);

        size_thing = sizeof(utxo->amount);
        deserialize_join(&size, data, &utxo->amount, size_thing);

        size_thing = sizeof(utxo->sender);
        deserialize_join(&size, data, utxo->sender, size_thing);

        size_thing = sizeof(utxo->lock_until);
        deserialize_join(&size, data, &utxo->lock_until, size_thing);

        size_thing = sizeof(utxo->data_size);
        deserialize_join(&size, data, &utxo->data_size, size_thing);

        size_thing = utxo->data_size;
        unsigned char *d = (unsigned char *)malloc(sizeof(unsigned char) * size_thing);
        deserialize_join(&size, data, d, size_thing);

        utxo->data = d;

        // 端序转换
        reverse((unsigned char *)&utxo->txid, 32);
        reverse((unsigned char *)&utxo->out, 1);
        reverse((unsigned char *)&utxo->timestamp, 4);
        reverse((unsigned char *)&utxo->type, 2);
        reverse((unsigned char *)&utxo->amount, 8);
        reverse((unsigned char *)&utxo->lock_until, 4);
        reverse((unsigned char *)&utxo->data_size, 2);

        arraylist_append(body.utxo_list, utxo);
    }

    return body;
}

static LWSPError reply_crc32(LWSProtocol *protocol, const unsigned char *data, const size_t len)
{
    uint32_t crc32 = 0;
    memcpy(&crc32, &data[len - 4], 4);
    uint32_t foot = protocol->hook->hook_crc32_get(protocol->hook->hook_crc32_context, data, len - 4);
    reverse((unsigned char *)&crc32, 4);
    if (foot != crc32) {
        return LWSPError_CRC32_Different;
    }

    return LWSPError_Success;
}

LWSPError protocol_listunspent_reply_handle(LWSProtocol *protocol, const unsigned char *data, const size_t len)
{
    LWSPError error = reply_crc32(protocol, data, len);
    if (LWSPError_Success != error) {
        return error;
    }

    unsigned char out[len];
    size_t out_len = 0;
    error = reply_remove_head(data, len, out, &out_len);
    if (LWSPError_Success == error) {
        struct ListUnspentBody body = listunspent_body_deserialize(out);

        // 全局状态
        memcpy(protocol->last_block_hash, body.block_hash, 32);
        protocol->last_block_height = body.block_height;
        protocol->last_block_time = body.block_time;

        // clear globle utxo list
        int i, len = protocol->utxo_list->length;
        // printf("utxo list length:%d\n", len);
        for (i = 0; i < len; i++) {
            struct UTXO *utxo = (struct UTXO *)protocol->utxo_list->data[i];
            if (!utxo && !utxo->data) {
                free(utxo->data);
                free(utxo);
            }
        }
        arraylist_clear(protocol->utxo_list);

        len = body.utxo_list->length;
        for (i = 0; i < len; i++) {
            struct UTXO *utxo = (struct UTXO *)body.utxo_list->data[i];
            arraylist_append(protocol->utxo_list, utxo);
        }

        arraylist_sort(protocol->utxo_list, compare_utxo);
        arraylist_clear(body.utxo_list);
        arraylist_free(body.utxo_list);
    } else {
        return error;
    }

    return LWSPError_Success;
}

LWSPError protocol_reply_info(LWSProtocol *protocol, const unsigned char *data, const size_t length, ReplyInfo *info)
{
    if (38 > length) {
        return LWSPError_Reply_Too_Short; // 数据长度错误
    }
    memcpy(info, data, 38);

    // 转小端序
    reverse((unsigned char *)&info->version, 2);
    reverse((unsigned char *)&info->error, 2);
    reverse((unsigned char *)&info->command, 2);

    return LWSPError_Success;
}

/**
 * @brief  calc_tx_fee
 * calc min transaction fee
 * @author shang
 * @email  shang_qd@qq.com
 * @date   2020/5/19 20:00
 * @param  nVchData *    vchdata size
 * @return static size_t -return vchdata fee
 */
static size_t calc_tx_fee(size_t nVchData)
{
    size_t nMinFee = 10000;
    if (0 == nVchData) {
        return nMinFee;
    }
    uint32_t multiplier = nVchData / 200;
    if (nVchData % 200 > 0) {
        multiplier++;
    }
    if (multiplier > 5) {
        return nMinFee + nMinFee * 10 + (multiplier - 5) * nMinFee * 4;
    } else {
        return nMinFee + multiplier * nMinFee * 2;
    }
}

static Transaction *transaction_new(LWSProtocol *protocol, const unsigned char *address, const TxVchData *vch_data)
{
    size_t list_len = protocol->utxo_list->length;
    struct UTXO *utxo = NULL;
    struct UTXO *utxo2 = NULL;

    if (0 == list_len) {
        return NULL;
    }

    utxo = (struct UTXO *)protocol->utxo_list->data[0];
    if (2 >= list_len) {
        utxo2 = (struct UTXO *)protocol->utxo_list->data[1];
    }

    if (NULL == utxo) {
        arraylist_clear(protocol->utxo_list);
        return NULL;
    }

    arraylist_remove(protocol->utxo_list, 0);
    if (utxo2 != NULL) {
        arraylist_remove(protocol->utxo_list, 1);
    }

    // VchData
    size_t uuid_session_size = 16;
    size_t timestamp_session_size = 4;
    size_t description_session_size = vch_data->desc_size + 1;
    size_t user_data_session_size = vch_data->len;

    size_t vch_data_len =
        uuid_session_size + timestamp_session_size + description_session_size + user_data_session_size;
    size_t fee = calc_tx_fee(vch_data_len);
    utxo->amount = utxo->amount - fee;
    if (utxo2 != NULL) {
        utxo->amount += utxo2->amount;
    }

    protocol->next_amount = utxo->amount; // Set global amount

    Transaction *tx = (Transaction *)malloc(sizeof(Transaction));
    memset(tx, 0x00, sizeof(Transaction));
    tx->version = 1;
    tx->type = 0x00;

    tx->timestamp = protocol->hook->hook_datetime_get(protocol->hook->hook_datetime_context);
    tx->lock_until = 0;
    // TODO: The protocol USES the hash of the previous block, but for now only forkid is used
    // memcpy(tx->hash_anchor, G.last_block_hash, 32);
    unsigned char fork[32];
    protocol->hook->hook_fork_get(protocol->hook->hook_fork_context, fork);

    memcpy(tx->hash_anchor, fork, 32);
    reverse(tx->hash_anchor, 32);

    tx->size0 = 1;
    if (utxo2 != NULL) {
        tx->size0 = 2;
    }
    int len = sizeof(unsigned char) * (32 + 1) * tx->size0;
    unsigned char *input = (unsigned char *)malloc(len);
    memcpy(input, utxo->txid, 32);
    memcpy(input + 32, &utxo->out, 1);
    if (utxo2 != NULL) {
        memcpy(input + 33, utxo2->txid, 32);
        memcpy(input + 65, &utxo2->out, 1);
    }
    tx->input = input;

    tx->prefix = 1;

    if (address) {
        memcpy(tx->address, address, sizeof(tx->address));
    }

    tx->tx_fee = fee;
    tx->amount = utxo->amount;
    unsigned char *data = (unsigned char *)malloc(vch_data_len);

    size_t size = 0;
    size_t size_thing = sizeof(vch_data->uuid);
    serialize_join(&size, (void *)vch_data->uuid, size_thing, data);

    size_thing = sizeof(vch_data->timestamp);
    serialize_join(&size, (void *)vch_data->timestamp, size_thing, data);

    unsigned char uc8 = vch_data->desc_size;
    serialize_join(&size, &uc8, 1, data);
    if (uc8 > 0) {
        size_thing = vch_data->desc_size;
        serialize_join(&size, vch_data->desc, size_thing, data);
    }

    size_thing = vch_data->len;
    serialize_join(&size, vch_data->data, size_thing, data);

    tx->size1 = size;
    tx->vch_data = data;

    tx->size2 = 64;

    return tx;
}

/**
 * @brief  transaction delete
 * Destroy a transaction instance
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2019/11/19 17:30:47
 * @param  LwsClient *      lws_client -LWS client
 * @param  Transaction *    tx         -transaction instance
 * @return  void
 */
static void transaction_delete(Transaction *tx)
{
    if (tx) {
        if (tx->vch_data) {
            free(tx->vch_data);
        }

        if (tx->input) {
            free(tx->input);
        }
        free(tx);
    }
}

/**
 * @brief  transaction_serialize_without_sign
 * Serialize Transaction to byte stream without sign
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2019/11/19 17:15:46
 * @param  Transaction *    tx   -input transaction instance
 * @param  unsigned char *  data -output byte stream
 * @return static size_t -byte stream length
 */
static size_t transaction_serialize_without_sign(Transaction *tx, unsigned char *data)
{
    size_t size = 0;
    size_t size_thing = sizeof(tx->version);
    serialize_join(&size, &tx->version, size_thing, data);

    size_thing = sizeof(tx->type);
    serialize_join(&size, &tx->type, size_thing, data);

    size_thing = sizeof(tx->timestamp);
    serialize_join(&size, &tx->timestamp, size_thing, data);

    size_thing = sizeof(tx->lock_until);
    serialize_join(&size, &tx->lock_until, size_thing, data);

    size_thing = sizeof(tx->hash_anchor);
    serialize_join(&size, tx->hash_anchor, size_thing, data);

    size_thing = sizeof(tx->size0);
    serialize_join(&size, &tx->size0, size_thing, data);

    size_thing = (sizeof(unsigned char) * (32 + 1)) * tx->size0;
    serialize_join(&size, tx->input, size_thing, data);

    size_thing = sizeof(tx->prefix);
    serialize_join(&size, &tx->prefix, size_thing, data);

    size_thing = sizeof(tx->address);
    serialize_join(&size, tx->address, size_thing, data);

    size_thing = sizeof(tx->amount);
    serialize_join(&size, &tx->amount, size_thing, data);

    size_thing = sizeof(tx->tx_fee);
    serialize_join(&size, &tx->tx_fee, size_thing, data);

    size_thing = sizeof(tx->size1);
    serialize_join(&size, &tx->size1, size_thing, data);

    size_thing = tx->size1;
    serialize_join(&size, tx->vch_data, size_thing, data);

    return size;
}

static int transaction_hash(LWSProtocol *protocol, const unsigned char *data, const size_t length,
                            const uint32_t timestamp, unsigned char *tx_id)
{
    protocol->hook->hook_blake2b_get(protocol->hook->hook_blake2b_context, data, length, tx_id);
    memcpy(tx_id + 28, &timestamp, 4);

    return 0;
}

/**
 * @brief  transaction_sign
 * Signature transaction
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2019/11/19 17:17:39
 * @param  LwsClient *      lws_client -LWS client
 * @param  Transaction *    tx         -input transaction instance
 * @return  LwsIoTError -return error code
 */
static int transaction_sign(LWSProtocol *protocol, Transaction *tx)
{
    unsigned char data[1024];
    size_t size = transaction_serialize_without_sign(tx, data);
    unsigned char sign[64] = {0};
    protocol->hook->hook_public_sign_ed25519(protocol->hook->hook_public_sign_ed25519_context, data, size, sign);
    memcpy(tx->sign, sign, tx->size2);

    return 0;
}

/**
 * @brief  transaction_serialize
 * Serialize transaction with signature
 * @author gaochun
 * @email  gaochun@dabank.io
 * @date   2019/11/19 17:19:13
 * @param  Transaction *    tx   -transaction instance
 * @param  unsigned char *  data -output byte stream
 * @return static size_t -return byte stream length
 */
static size_t transaction_serialize(Transaction *tx, unsigned char *data)
{
    size_t size = transaction_serialize_without_sign(tx, data);

    size_t size_thing = sizeof(tx->size2);
    serialize_join(&size, &tx->size2, size_thing, data);

    size_thing = tx->size2;
    serialize_join(&size, tx->sign, size_thing, data);

    return size;
}

LWSPError protocol_sendtx_request(LWSProtocol *protocol, const unsigned char *address, const TxVchData *vch,
                                  sha256_hash hash, unsigned char *data, size_t *length)
{
    if (NULL == protocol) {
        return LWSPError_Protocol_NULL;
    }

    if (NULL == protocol->hook) {
        return LWSPError_Hook_NULL;
    }

    // 创建Tx结构体
    Transaction *tx = transaction_new(protocol, address, vch);
    if (NULL == tx) {
        return LWSPError_Create_Tx_Error;
    }

    // 签名
    transaction_sign(protocol, tx);

    // 序列化Tx
    unsigned char tx_data[1024];
    size_t tx_data_len = 0;
    tx_data_len = transaction_serialize(tx, tx_data);
    if (0 >= tx_data_len) {
        return LWSPError_Serialize_Tx_Error;
    }

    char hex[tx_data_len * 2 + 1];
    memset(hex, 0x00, tx_data_len * 2 + 1);
    sodium_bin2hex(hex, tx_data_len * 2 + 1, tx_data, tx_data_len);
    printf("tx-> length:%ld, hex:%s\n", tx_data_len, hex);

    // 创建send tx请求
    struct SendTxRequest request;
    request.nonce = protocol->hook->hook_nonce_get(protocol->hook->hook_nonce_context);
    transaction_hash(protocol, tx_data, tx_data_len, tx->timestamp, request.tx_id);
    protocol->hook->hook_fork_get(protocol->hook->hook_fork_context, request.fork_id);
    request.data_size = tx_data_len;

    // char hex1[65];
    // memset(hex1, 0x00, 65);
    // sodium_bin2hex(hex1, 65, request.tx_id, 32);
    // printf("tx_id-> length:%d, hex:%s\n", 32, hex1);

    // 序列化send tx请求
    size_t body_len = 4 + 32 + 32 + 2 + tx_data_len + 2;
    request.tx_data = tx_data;
    unsigned char body[body_len];
    uint16_t command = SendTx;
    memcpy(body, &command, 2);
    memcpy(&body[2], &request, body_len - tx_data_len - 2);
    memcpy(&body[72], request.tx_data, tx_data_len);

    // char hex2[body_len * 2 + 1];
    // memset(hex2, 0x00, body_len * 2 + 1);
    // sodium_bin2hex(hex2, body_len * 2 + 1, body, body_len);
    // printf("body-> length:%ld, hex:%s\n", body_len, hex2);

    protocol->hook->hook_sha256_get(protocol->hook->hook_sha256_context, body, body_len, hash);

    // 生成请求
    wrap_request(protocol, body, body_len, hash, data, length);
    protocol->sendtx_index++;

    // 删除tx
    transaction_delete(tx);

    return LWSPError_Success;
}

static struct SendTxBody sendtx_body_deserialize(const unsigned char *data)
{
    struct SendTxBody body;
    size_t size = 0;
    size_t size_thing = sizeof(body.command);
    deserialize_join(&size, data, &body.command, size_thing);

    size_thing = sizeof(body.nonce);
    deserialize_join(&size, data, &body.nonce, size_thing);

    size_thing = sizeof(body.tx_id);
    deserialize_join(&size, data, body.tx_id, size_thing);

    reverse((unsigned char *)&body.command, 2);
    reverse((unsigned char *)&body.nonce, 4);
    reverse((unsigned char *)&body.tx_id, 32);

    return body;
}

LWSPError protocol_sendtx_reply_handle(LWSProtocol *protocol, const unsigned char *data, const size_t len)
{
    unsigned char out[len];
    size_t out_len = 0;
    LWSPError error = reply_remove_head(data, len, out, &out_len);
    if (LWSPError_Success == error) {
        struct SendTxBody body = sendtx_body_deserialize(out);

        // Append tx to utxo list
        struct UTXO *utxo = (struct UTXO *)malloc(sizeof(struct UTXO));
        memcpy(utxo->txid, body.tx_id, 32);

        utxo->amount = protocol->next_amount;
        arraylist_append(protocol->utxo_list, utxo);
    } else {
        return error;
    }

    return LWSPError_Success;
}

LWSPError protocol_delete(LWSProtocol *protocol)
{
    if (NULL == protocol) {
        return LWSPError_Protocol_NULL;
    }

    if (NULL != protocol->hook) {
        free(protocol->hook);
    }

    free(protocol);

    return LWSPError_Success;
}