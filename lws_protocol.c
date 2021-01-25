#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
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

// /// sdk全局变量
// static struct {
//     uint16_t service_nonce;
//     uint16_t sync_nonce;
//     uint16_t sendtx_nonce;
//     ed25519_public_key pk;
//     big_num fork;
//     char id[100];

//     uint32_t address_id;
//     unsigned char fork_bitmap[8];
//     key_seed seed;

//     void *nonce_ctx;
//     void *datetime_ctx;
//     void *device_id_ctx;
//     void *fork_ctx;
//     void *public_key_ctx;
//     void *shared_key_ctx;
//     void *blake2b_ctx;
//     void *sign_ed25519_ctx;

//     NonceGet nonce_get;
//     DatetimeGet datetime_get;
//     DeviceIDGet device_id_get;
//     ForkGet fork_get;
//     PublicKeyGet public_key_get;
//     SharedKeyGet shared_key_get;
//     Blake2bGet blake2b_get;
//     SignEd25519 sign_ed25519_get;

//     ArrayList *utxo_list;
//     unsigned char last_block_hash[32];
//     uint32_t last_block_height;
//     uint32_t last_block_time;
// } G;

/// 交易结构体
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

// /// 客户端验证请求结构体
// struct ServiceReq {
//     uint16_t nonce;
//     uint8_t prefix;
//     unsigned char address[32];
//     uint32_t version;
//     uint32_t timestamp;
//     uint8_t fork_num;
//     unsigned char *fork_list;
//     uint16_t reply_utxo;
//     char *topic_prefix;
//     uint16_t sign_size;
//     unsigned char sign[64];
//     ed25519_secret_key sk;
//     ed25519_public_key pk;
// };

// /// 客户端验证响应结构体
// struct _ServiceReply {
//     uint16_t nonce;
//     uint32_t version;
//     uint8_t error;
//     uint32_t address_id;
//     unsigned char fork_bitmap[8];
//     key_seed seed;
// };

// /// 数据同步请求结构体
// struct SyncReq {
//     uint16_t nonce;
//     uint32_t address_id;
//     unsigned char fork_id[32];
//     blake2b_hash utxo_hash;
//     unsigned char signature[20];
// };

// /// 数据同步响应结构体
// struct _SyncReply {
//     uint16_t nonce;
//     uint8_t error;
//     unsigned char block_hash[32];
//     uint32_t block_height;
//     uint32_t block_time;
//     uint16_t utxo_num;
//     ArrayList *utxo_list;
//     uint8_t continue_flag;
// };

// /// UTXO struct
// struct UTXO {
//     unsigned char txid[32];
//     uint8_t out;
//     uint32_t block_height;
//     uint16_t type;
//     uint64_t amount;
//     unsigned char sender[33];
//     uint32_t lock_until;
//     uint16_t data_size;
//     unsigned char *data;
//     uint64_t new_amount;
//     int is_used;
// };

// struct UTXOIndex {
//     unsigned char txid[32];
//     uint8_t out;
// };

// struct UTXOUpdateItem {
//     uint8_t op_type;
//     struct UTXOIndex index;
//     uint32_t blocke_height;
//     struct UTXO new_utxo;
// };

// struct UTXOUpdate {
//     uint16_t nonce;
//     uint32_t address_id;
//     unsigned char fork_id[32];
//     unsigned char block_hash[32];
//     uint32_t block_height;
//     uint32_t block_time;
//     uint16_t update_num;
//     // ArrayList *update_list;
//     uint8_t continue_flag;
// };

// struct UTXOAbort {
//     uint16_t nonce;
//     uint32_t address_id;
//     uint8_t reason;
//     unsigned char signature[20];
// };

// struct SendTxReq {
//     uint16_t nonce;
//     uint32_t address_id;
//     unsigned char fork_id[32];
//     uint8_t *tx_data;
//     unsigned char signature[20];
// };

// struct SendTxReply {
//     uint16_t nonce;
//     uint8_t error;
//     uint8_t err_code;
//     char txid[65];
//     char *err_desc;
// };

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
 *
 *
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

// int hook_nonce_get(const NonceGet callback, void *ctx)
// {
//     G.nonce_get = callback;
//     G.nonce_ctx = ctx;
//     return 0;
// }

// int hook_datetime_get(const DatetimeGet callback, void *ctx)
// {
//     G.datetime_get = callback;
//     G.datetime_ctx = ctx;
//     return 0;
// }

// int hook_device_id_get(const DeviceIDGet callback, void *ctx)
// {
//     G.device_id_get = callback;
//     G.device_id_ctx = ctx;
//     return 0;
// }

// int hook_fork_get(const ForkGet callback, void *ctx)
// {
//     G.fork_get = callback;
//     G.fork_ctx = ctx;
//     return 0;
// }

// int hook_public_key_get(const PublicKeyGet callback, void *ctx)
// {
//     G.public_key_get = callback;
//     G.public_key_ctx = ctx;
//     return 0;
// }

// int hook_shared_key_get(const SharedKeyGet callback, void *ctx)
// {

//     G.shared_key_get = callback;
//     G.shared_key_ctx = ctx;
//     return 0;
// }

// int hook_blake2b_get(const Blake2bGet callback, void *ctx)
// {
//     G.blake2b_get = callback;
//     G.blake2b_ctx = ctx;
//     return 0;
// }

// int hook_public_sign_ed25519(const SignEd25519 callback, void *ctx)
// {
//     G.sign_ed25519_get = callback;
//     G.sign_ed25519_ctx = ctx;
//     return 0;
// }

/**
 * @brief  serialize_join
 * serialize unsigned char array
 *
 *
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
 *
 *
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

// /**
//  * @brief  equal_utxo
//  * Detemine if v1(UTXO) and v1(UTXOIndex) are equal
//  *
//  *
//  * @author gaochun
//  * @email  gaochun@dabank.io
//  * @date   2019/11/18 17:43:53
//  * @param  ArrayListValue   v1 -input UTXO
//  * @param  ArrayListValue   v2 -input UTXOIndex
//  * @return static int -if equal return 1, else return 0
//  */
// static int equal_utxo(ArrayListValue v1, ArrayListValue v2)
// {
//     struct UTXO *utxo = (struct UTXO *)v1;
//     struct UTXOIndex *index = (struct UTXOIndex *)v2;

//     big_num txid1, txid2;
//     memcpy(txid1, utxo->txid, 32);
//     memcpy(txid2, index->txid, 32);

//     int ret = big_num_compare(txid1, txid2);

//     // sort rule--ArrayListEqualFunc
//     // https://fragglet.github.io/c-algorithms/doc/arraylist_8h.html

//     // utxo == utxo2
//     if (0 == ret) {
//         if (utxo->out == index->out) {
//             return 1;
//         }
//         return 0;
//     }

//     return 0;
// }

// /**
//  * @brief  compare_utxo
//  * Compare v1(UTXO) and v2(UTXO)
//  *
//  *
//  * @author gaochun
//  * @email  gaochun@dabank.io
//  * @date   2019/11/18 17:50:58
//  * @param  ArrayListValue   v1 -input UTXO instance
//  * @param  ArrayListValue   v2 -input UTXO instance
//  * @return static int --if equal return 0, v1 greater then v2 return 1, else return -1
//  */
// static int compare_utxo(ArrayListValue v1, ArrayListValue v2)
// {
//     struct UTXO *utxo1 = (struct UTXO *)v1;
//     struct UTXO *utxo2 = (struct UTXO *)v2;

//     big_num txid1, txid2;
//     memcpy(txid1, utxo1->txid, 32);
//     memcpy(txid2, utxo2->txid, 32);

//     int ret = big_num_compare(txid1, txid2);

//     // sort rule--ArrayListCompareFunc
//     // https://fragglet.github.io/c-algorithms/doc/arraylist_8h.html

//     // utxo == utxo2
//     if (0 == ret) {
//         if (utxo1->out == utxo2->out) {
//             // log_trace("##compare_utxo# utxo1 eq utxo2"); // hex
//             return 0;
//         }

//         if (utxo1->out > utxo2->out) {
//             return 1;
//         }

//         if (utxo1->out < utxo2->out) {
//             return -1;
//         }
//     }

//     // utxo1 > utxo2
//     if (1 == ret) {
//         return 1;
//     }

//     // utxo1 < utxo2
//     if (-1 == ret) {
//         return -1;
//     }

//     return -1;
// }

// /**
//  * @brief  utxo_hash
//  * hash UTXO list
//  *
//  *
//  * @author gaochun
//  * @email  gaochun@dabank.io
//  * @date   2020/9/16 17:22:43
//  * @param  ArrayList *      array_list
//  * @param  blake2b_hash     hash
//  * @return static void
//  */
// static void utxo_hash(ArrayList *array_list, blake2b_hash hash)
// {
//     if (!array_list) {
//         return;
//     }

//     size_t len = array_list->length;
//     if (0 >= len) {
//         return;
//     }

//     int data_size = len * (32 + sizeof(uint8_t) + sizeof(uint32_t));
//     uint8_t *data = (uint8_t *)malloc(data_size);

//     size_t size = 0;

//     int i;
//     for (i = 0; i < len; i++) {
//         struct UTXO *utxo = (struct UTXO *)array_list->data[i];

//         size_t size_thing = sizeof(utxo->txid);
//         serialize_join(&size, utxo->txid, size_thing, data);

//         size_thing = sizeof(utxo->out);
//         serialize_join(&size, &utxo->out, size_thing, data);

//         size_thing = sizeof(utxo->block_height);
//         serialize_join(&size, &utxo->block_height, size_thing, data);
//     }

//     G.blake2b_get(G.blake2b_ctx, data, size, hash);

//     free(data);

//     return;
// }

// /**
//  * @brief  service_req_serialize
//  * ServiceReq object serialized to bytes(unsigned char)
//  *
//  *
//  * @author gaochun
//  * @email  gaochun@dabank.io
//  * @date   2019/11/18 17:32:58
//  * @param  struct ServiceReq * req
//  * @param  unsigned char *  data
//  * @return static size_t
//  */
// static size_t service_req_serialize(struct ServiceReq *req, unsigned char *data)
// {
//     size_t size = 0;
//     size_t size_thing = sizeof(req->nonce);
//     serialize_join(&size, &req->nonce, size_thing, data);

//     size_thing = sizeof(req->prefix);
//     serialize_join(&size, &req->prefix, size_thing, data);

//     size_thing = sizeof(req->address);
//     serialize_join(&size, &req->address, size_thing, data);

//     size_thing = sizeof(req->version);
//     serialize_join(&size, &req->version, size_thing, data);

//     size_thing = sizeof(req->timestamp);
//     serialize_join(&size, &req->timestamp, size_thing, data);

//     size_thing = sizeof(req->fork_num);
//     serialize_join(&size, &req->fork_num, size_thing, data);

//     size_thing = sizeof(unsigned char) * 32;
//     serialize_join(&size, req->fork_list, size_thing, data);

//     size_thing = sizeof(req->reply_utxo);
//     serialize_join(&size, &req->reply_utxo, size_thing, data);

//     size_thing = strlen(req->topic_prefix) + 1;
//     serialize_join(&size, req->topic_prefix, size_thing, data);

//     unsigned char buff[64] = {0};
//     G.sign_ed25519_get(G.sign_ed25519_ctx, data, size, buff);

//     // TODO:签名位置
//     req->sign_size = sizeof(buff);

//     size_thing = sizeof(req->sign_size);
//     serialize_join(&size, &req->sign_size, size_thing, data);

//     size_thing = sizeof(buff);
//     serialize_join(&size, buff, size_thing, data);

//     return size;
// }

// static ServiceReply service_reply_deserialize(const unsigned char *data)
// {
//     ServiceReply service_reply;
//     size_t size = 0;
//     size_t size_thing = sizeof(service_reply.nonce);
//     deserialize_join(&size, data, &service_reply.nonce, size_thing);

//     size_thing = sizeof(service_reply.version);
//     deserialize_join(&size, data, &service_reply.version, size_thing);

//     size_thing = sizeof(service_reply.error);
//     deserialize_join(&size, data, &service_reply.error, size_thing);

//     size_thing = sizeof(service_reply.address_id);
//     deserialize_join(&size, data, &service_reply.address_id, size_thing);

//     size_thing = sizeof(service_reply.fork_bitmap);
//     deserialize_join(&size, data, service_reply.fork_bitmap, size_thing);

//     size_thing = sizeof(service_reply.seed);
//     deserialize_join(&size, data, service_reply.seed, size_thing);

//     return service_reply;
// }

// /**
//  * @brief  sync_reply_deserialize
//  * SyncReply deserialize
//  *
//  *
//  * @author gaochun
//  * @email  gaochun@dabank.io
//  * @date   2019/11/18 18:5:41
//  * @param  unsigned char *  data -SyncReply serialized data from LWS
//  * @return static struct SyncReply -deserialized SyncReply object
//  */
// static SyncReply sync_reply_deserialize(const unsigned char *data)
// {
//     SyncReply sync_reply;
//     sync_reply.utxo_list = arraylist_new(0);
//     size_t size = 0;
//     size_t size_thing = sizeof(sync_reply.nonce);
//     deserialize_join(&size, data, &sync_reply.nonce, size_thing);

//     size_thing = sizeof(sync_reply.error);
//     deserialize_join(&size, data, &sync_reply.error, size_thing);

//     if (sync_reply.error > 1) {
//         return sync_reply;
//     }

//     size_thing = sizeof(sync_reply.block_hash);
//     deserialize_join(&size, data, &sync_reply.block_hash, size_thing);

//     size_thing = sizeof(sync_reply.block_height);
//     deserialize_join(&size, data, &sync_reply.block_height, size_thing);

//     size_thing = sizeof(sync_reply.block_time);
//     deserialize_join(&size, data, &sync_reply.block_time, size_thing);

//     size_thing = sizeof(sync_reply.utxo_num);
//     deserialize_join(&size, data, &sync_reply.utxo_num, size_thing);

//     // UTXOList
//     int i;
//     for (i = 0; i < sync_reply.utxo_num; i++) {
//         struct UTXO *utxo = (struct UTXO *)malloc(sizeof(struct UTXO));

//         size_thing = sizeof(utxo->txid);
//         deserialize_join(&size, data, utxo->txid, size_thing);

//         size_thing = sizeof(utxo->out);
//         deserialize_join(&size, data, &utxo->out, size_thing);

//         size_thing = sizeof(utxo->block_height);
//         deserialize_join(&size, data, &utxo->block_height, size_thing);

//         size_thing = sizeof(utxo->type);
//         deserialize_join(&size, data, &utxo->type, size_thing);

//         size_thing = sizeof(utxo->amount);
//         deserialize_join(&size, data, &utxo->amount, size_thing);

//         size_thing = sizeof(utxo->sender);
//         deserialize_join(&size, data, utxo->sender, size_thing);

//         size_thing = sizeof(utxo->lock_until);
//         deserialize_join(&size, data, &utxo->lock_until, size_thing);

//         size_thing = sizeof(utxo->data_size);
//         deserialize_join(&size, data, &utxo->data_size, size_thing);

//         size_thing = utxo->data_size;
//         unsigned char *d = (unsigned char *)malloc(sizeof(unsigned char) * size_thing);
//         deserialize_join(&size, data, d, size_thing);

//         utxo->data = d;

//         arraylist_append(sync_reply.utxo_list, utxo);
//     }

//     size_thing = sizeof(sync_reply.continue_flag);
//     deserialize_join(&size, data, &sync_reply.continue_flag, size_thing);

//     return sync_reply;
// }

// /**
//  * @brief  create_service_req
//  * Create service request objuect
//  *
//  *
//  * @author gaochun
//  * @email  gaochun@dabank.io
//  * @date   2019/11/18 17:17:12
//  * @param  LwsClient *      lws_client -LWS client
//  * @return static struct ServiceReq -serviceReq instance
//  */
// static struct ServiceReq create_service_req()
// {
//     time_t now_time = G.datetime_get(G.datetime_ctx);
//     G.service_nonce = G.nonce_get(G.nonce_ctx);

//     struct ServiceReq service_req;
//     memset(&service_req, 0x00, sizeof(struct ServiceReq));
//     service_req.nonce = G.service_nonce;
//     service_req.prefix = 1;
//     memcpy(service_req.address, G.pk, 32);
//     service_req.version = 1;
//     service_req.timestamp = now_time;
//     service_req.fork_num = 1;
//     service_req.fork_list = G.fork;
//     service_req.reply_utxo = 0;
//     service_req.topic_prefix = G.id;
//     memcpy(&service_req.pk[0], G.pk, 32);

//     return service_req;
// }

// static struct SyncReq create_sync_req(const ServiceReply *service_reply)
// {
//     G.sync_nonce = G.nonce_get(G.nonce_ctx);

//     struct SyncReq sync_req;
//     memset(&sync_req, 0x00, sizeof(struct SyncReq));
//     sync_req.nonce = G.sync_nonce;
//     sync_req.address_id = service_reply->address_id;
//     memcpy(sync_req.fork_id, G.fork, 32);

//     unsigned char data[100] = {'\0'};
//     size_t size = 0;
//     size_t size_thing = sizeof(sync_req.nonce);
//     serialize_join(&size, &sync_req.nonce, size_thing, data);

//     size_thing = sizeof(sync_req.address_id);
//     serialize_join(&size, &sync_req.address_id, size_thing, data);

//     size_thing = sizeof(sync_req.fork_id);
//     serialize_join(&size, &sync_req.fork_id, size_thing, data);

//     // utxo_hash
//     utxo_hash(G.utxo_list, sync_req.utxo_hash);

//     size_thing = sizeof(sync_req.utxo_hash);
//     serialize_join(&size, &sync_req.utxo_hash, size_thing, data);

//     // signature
//     unsigned char sig_buff[20];
//     G.shared_key_get(G.shared_key_ctx, service_reply->seed, data, size, sig_buff);

//     memcpy(sync_req.signature, sig_buff, 20);

//     return sync_req;
// }

// /**
//  * @brief  sync_req_serialize
//  * SyncReq serialize
//  *
//  *
//  * @author gaochun
//  * @email  gaochun@dabank.io
//  * @date   2019/11/18 18:3:40
//  * @param  struct SyncReq * req  -SyncReq instance
//  * @param  unsigned char *  data -SyncReq serialized bytes
//  * @return static size_t -data length(bytes len)
//  */
// static size_t sync_req_serialize(struct SyncReq *req, unsigned char *data)
// {

//     size_t size = 0;
//     size_t size_thing = sizeof(req->nonce);
//     serialize_join(&size, &req->nonce, size_thing, data);

//     size_thing = sizeof(req->address_id);
//     serialize_join(&size, &req->address_id, size_thing, data);

//     size_thing = sizeof(req->fork_id);
//     serialize_join(&size, &req->fork_id, size_thing, data);

//     size_thing = sizeof(req->utxo_hash);
//     serialize_join(&size, &req->utxo_hash, size_thing, data);

//     size_thing = sizeof(req->signature);
//     serialize_join(&size, &req->signature, size_thing, data);

//     return size;
// }

// /**
//  * @brief  calc_tx_fee
//  * calc min transaction fee
//  *
//  *
//  * @author shang
//  * @email  shang_qd@qq.com
//  * @date   2020/5/19 20:00
//  * @param  nVchData *    vchdata size
//  * @return static size_t -return vchdata fee
//  */
// static size_t calc_tx_fee(size_t nVchData)
// {
//     size_t nMinFee = 10000;
//     if (0 == nVchData) {
//         return nMinFee;
//     }
//     uint32_t multiplier = nVchData / 200;
//     if (nVchData % 200 > 0) {
//         multiplier++;
//     }
//     if (multiplier > 5) {
//         return nMinFee + nMinFee * 10 + (multiplier - 5) * nMinFee * 4;
//     } else {
//         return nMinFee + multiplier * nMinFee * 2;
//     }
// }

// static Transaction *lws_create_tx(const unsigned char *address, const VchData *vch_data)
// {
//     size_t list_len = G.utxo_list->length;
//     struct UTXO *utxo = NULL;
//     struct UTXO *utxo2 = NULL;

//     int j = 0, count = 0;
//     for (j = 0; j < list_len; j++) {
//         if (1 != ((struct UTXO *)G.utxo_list->data[j])->is_used) {
//             count++;
//         }
//     }

//     int index = 0;
//     for (int i = 0; i < list_len; i++) {
//         if (1 != ((struct UTXO *)G.utxo_list->data[i])->is_used) {
//             if (utxo == NULL) {
//                 utxo = (struct UTXO *)G.utxo_list->data[i];
//             } else {
//                 if (utxo2 == NULL) {
//                     utxo2 = (struct UTXO *)G.utxo_list->data[i];
//                     index = i;
//                 }
//             }
//             if (utxo != NULL && utxo2 != NULL) {
//                 break;
//             }
//         }
//     }

//     if (!utxo) {
//         arraylist_clear(G.utxo_list);
//         return NULL;
//     }

//     struct UTXO new_utxo;
//     struct UTXO new_utxo2;
//     memcpy(&new_utxo, utxo, sizeof(struct UTXO));
//     if (utxo2 != NULL) {
//         memcpy(&new_utxo2, utxo2, sizeof(struct UTXO));
//     }
//     utxo->is_used = 1; // set this utxo is used
//     if (utxo2 != NULL) {
//         arraylist_remove(G.utxo_list, index);
//     }
//     // VchData
//     size_t uuid_session_size = 16;
//     size_t timestamp_session_size = 4;
//     size_t description_session_size = vch_data->desc_size + 1;
//     size_t user_data_session_size = vch_data->len;

//     size_t vch_data_len =
//         uuid_session_size + timestamp_session_size + description_session_size + user_data_session_size;
//     size_t fee = calc_tx_fee(vch_data_len);
//     utxo->new_amount = utxo->amount - fee;
//     if (utxo2 != NULL) {
//         utxo->new_amount += new_utxo2.amount;
//     }
//     new_utxo.new_amount = utxo->new_amount;

//     Transaction *tx = (Transaction *)malloc(sizeof(Transaction));
//     memset(tx, 0x00, sizeof(Transaction));
//     tx->version = 1;
//     tx->type = 0x00;

//     tx->timestamp = G.datetime_get(G.datetime_ctx);
//     tx->lock_until = 0;
//     // TODO: The protocol USES the hash of the previous block, but for now only forkid is used
//     // memcpy(tx->hash_anchor, G.last_block_hash, 32);
//     memcpy(tx->hash_anchor, G.fork, 32);
//     reverse(tx->hash_anchor, 32);

//     tx->size0 = 1;
//     if (utxo2 != NULL) {
//         tx->size0 = 2;
//     }
//     int len = sizeof(unsigned char) * (32 + 1) * tx->size0;
//     unsigned char *input = (unsigned char *)malloc(len);
//     memcpy(input, new_utxo.txid, 32);
//     memcpy(input + 32, &new_utxo.out, 1);
//     if (utxo2 != NULL) {
//         memcpy(input + 33, new_utxo2.txid, 32);
//         memcpy(input + 65, &new_utxo2.out, 1);
//     }
//     tx->input = input;

//     tx->prefix = 1;

//     if (address) {
//         memcpy(tx->address, address, sizeof(tx->address));
//     } else {
//         // memcpy(tx->address, &lws_client->pubkey, sizeof(tx->address));
//         memcpy(tx->address, &G.pk[0], sizeof(tx->address));
//     }

//     tx->tx_fee = fee;
//     tx->amount = new_utxo.new_amount;
//     unsigned char *data = (unsigned char *)malloc(vch_data_len);

//     size_t size = 0;
//     size_t size_thing = sizeof(vch_data->uuid);
//     serialize_join(&size, (void *)vch_data->uuid, size_thing, data);

//     size_thing = sizeof(vch_data->timestamp);
//     serialize_join(&size, (void *)vch_data->timestamp, size_thing, data);

//     unsigned char uc8 = vch_data->desc_size;
//     serialize_join(&size, &uc8, 1, data);
//     if (uc8 > 0) {
//         size_thing = vch_data->desc_size;
//         serialize_join(&size, vch_data->desc, size_thing, data);
//     }

//     size_thing = vch_data->len;
//     serialize_join(&size, vch_data->data, size_thing, data);

//     tx->size1 = size;
//     tx->vch_data = data;

//     tx->size2 = 64;

//     return tx;
// }

// /**
//  * @brief  tx_serialize_without_sign
//  * Serialize Transaction to byte stream without sign
//  *
//  *
//  * @author gaochun
//  * @email  gaochun@dabank.io
//  * @date   2019/11/19 17:15:46
//  * @param  Transaction *    tx   -input transaction instance
//  * @param  unsigned char *  data -output byte stream
//  * @return static size_t -byte stream length
//  */
// static size_t tx_serialize_without_sign(Transaction *tx, unsigned char *data)
// {
//     size_t size = 0;
//     size_t size_thing = sizeof(tx->version);
//     serialize_join(&size, &tx->version, size_thing, data);

//     size_thing = sizeof(tx->type);
//     serialize_join(&size, &tx->type, size_thing, data);

//     size_thing = sizeof(tx->timestamp);
//     serialize_join(&size, &tx->timestamp, size_thing, data);

//     size_thing = sizeof(tx->lock_until);
//     serialize_join(&size, &tx->lock_until, size_thing, data);

//     size_thing = sizeof(tx->hash_anchor);
//     serialize_join(&size, tx->hash_anchor, size_thing, data);

//     size_thing = sizeof(tx->size0);
//     serialize_join(&size, &tx->size0, size_thing, data);

//     size_thing = (sizeof(unsigned char) * (32 + 1)) * tx->size0;
//     serialize_join(&size, tx->input, size_thing, data);

//     size_thing = sizeof(tx->prefix);
//     serialize_join(&size, &tx->prefix, size_thing, data);

//     size_thing = sizeof(tx->address);
//     serialize_join(&size, tx->address, size_thing, data);

//     size_thing = sizeof(tx->amount);
//     serialize_join(&size, &tx->amount, size_thing, data);

//     size_thing = sizeof(tx->tx_fee);
//     serialize_join(&size, &tx->tx_fee, size_thing, data);

//     size_thing = sizeof(tx->size1);
//     serialize_join(&size, &tx->size1, size_thing, data);

//     size_thing = tx->size1;
//     serialize_join(&size, tx->vch_data, size_thing, data);

//     return size;
// }

// /**
//  * @brief  lwsiot_sign_tx
//  * Signature transaction
//  *
//  *
//  * @author gaochun
//  * @email  gaochun@dabank.io
//  * @date   2019/11/19 17:17:39
//  * @param  LwsClient *      lws_client -LWS client
//  * @param  Transaction *    tx         -input transaction instance
//  * @return  LwsIoTError -return error code
//  */
// static int lws_sign_tx(Transaction *tx)
// {
//     unsigned char data[4096];
//     size_t size = tx_serialize_without_sign(tx, data);
//     unsigned char sign[64] = {0};
//     G.sign_ed25519_get(G.sign_ed25519_ctx, data, size, sign);
//     memcpy(tx->sign, sign, tx->size2);

//     return 0;
// }

// /**
//  * @brief  tx_serialize
//  * Serialize transaction with signature
//  *
//  *
//  * @author gaochun
//  * @email  gaochun@dabank.io
//  * @date   2019/11/19 17:19:13
//  * @param  Transaction *    tx   -transaction instance
//  * @param  unsigned char *  data -output byte stream
//  * @return static size_t -return byte stream length
//  */
// static size_t tx_serialize(Transaction *tx, unsigned char *data)
// {
//     size_t size = tx_serialize_without_sign(tx, data);

//     size_t size_thing = sizeof(tx->size2);
//     serialize_join(&size, &tx->size2, size_thing, data);

//     size_thing = tx->size2;
//     serialize_join(&size, tx->sign, size_thing, data);

//     return size;
// }

// /**
//  * @brief  sendtx_req_serialize_without_sign
//  * Serialize SendTxReq to byte stream
//  *
//  *
//  * @author gaochun
//  * @email  gaochun@dabank.io
//  * @date   2019/11/19 16:44:39
//  * @param  struct SendTxReq * req -input SendTxReq instance
//  * @param  size_t           len   -output&input data length, default 0
//  * @param  unsigned char *  data  -serialized data
//  * @return static size_t -same to argument len
//  */
// static size_t sendtx_req_serialize_without_sign(struct SendTxReq *req, size_t len, unsigned char *data)
// {
//     size_t size = 0;
//     size_t size_thing = sizeof(req->nonce);
//     serialize_join(&size, &req->nonce, size_thing, data);

//     size_thing = sizeof(req->address_id);
//     serialize_join(&size, &req->address_id, size_thing, data);

//     size_thing = sizeof(req->fork_id);
//     serialize_join(&size, req->fork_id, size_thing, data);

//     size_thing = len;
//     serialize_join(&size, req->tx_data, size_thing, data);

//     return size;
// }

// /**
//  * @brief  create_sendtx_req
//  * Create a SendTxReq command object
//  *
//  *
//  * @author gaochun
//  * @email  gaochun@dabank.io
//  * @date   2019/11/19 16:47:25
//  * @param  LwsClient *      lws_client -LWS client
//  * @param  unsigned char *  tx_data    -input tx data stream
//  * @param  size_t           len        -input data length
//  * @return static struct SendTxReq -return SentTxReq instance
//  */
// static struct SendTxReq create_sendtx_req(unsigned char *tx_data, size_t len)
// {
//     struct SendTxReq sendtx_req;
//     memset(&sendtx_req, 0x00, sizeof(struct SendTxReq));

//     sendtx_req.nonce = G.nonce_get(G.nonce_ctx);
//     G.sendtx_nonce = sendtx_req.nonce;

//     sendtx_req.address_id = G.address_id;

//     memcpy(sendtx_req.fork_id, G.fork, 32);

//     sendtx_req.tx_data = tx_data;

//     unsigned char data[4096];
//     size_t size = sendtx_req_serialize_without_sign(&sendtx_req, len, data);

//     // signature
//     unsigned char sign[20];
//     G.shared_key_get(G.shared_key_ctx, G.seed, data, size, sign);

//     memcpy(sendtx_req.signature, sign, sizeof(sign));

//     return sendtx_req;
// }

// /**
//  * @brief  sendtx_req_serialize
//  * Serialize SendTxReq to byte stream
//  *
//  *
//  * @author gaochun
//  * @email  gaochun@dabank.io
//  * @date   2019/11/19 16:50:52
//  * @param  struct SendTxReq * req       -input SendTxReq instance
//  * @param  size_t           tx_data_len -output length of target byte stream
//  * @param  unsigned char *  data        -serialized byte stream
//  * @return static size_t -return output length of target byte stream same as argument tx_data_len
//  */
// static size_t sendtx_req_serialize(struct SendTxReq *req, size_t tx_data_len, unsigned char *data)
// {
//     size_t size = sendtx_req_serialize_without_sign(req, tx_data_len, data);
//     size_t size_thing = sizeof(req->signature);
//     serialize_join(&size, req->signature, size_thing, data);

//     return size;
// }

// /**
//  * @brief  sendtx_reply_deserialize
//  * SendtxReply deserialize
//  *
//  *
//  * @author gaochun
//  * @email  gaochun@dabank.io
//  * @date   2019/11/19 16:39:37
//  * @param  unsigned char *  data -serialized byte data from LWS
//  * @return static struct SendTxReply -deserialized SendTxReply object
//  */
// static struct SendTxReply sendtx_reply_deserialize(const unsigned char *data)
// {
//     struct SendTxReply sendtx_reply;
//     memset(&sendtx_reply, 0x00, sizeof(struct SendTxReply));

//     size_t size = 0;
//     size_t size_thing = sizeof(sendtx_reply.nonce);
//     deserialize_join(&size, data, &sendtx_reply.nonce, size_thing);

//     size_thing = sizeof(sendtx_reply.error);
//     deserialize_join(&size, data, &sendtx_reply.error, size_thing);

//     size_thing = sizeof(sendtx_reply.err_code);
//     deserialize_join(&size, data, &sendtx_reply.err_code, size_thing);

//     size_thing = sizeof(sendtx_reply.txid);
//     deserialize_join(&size, data, sendtx_reply.txid, size_thing);

//     size_t str_len = strlen((char *)(data + size));
//     char *str = (char *)malloc(str_len + 1);
//     memset(str, 0x00, str_len + 1);
//     strncpy(str, (char *)(data + size), str_len);
//     sendtx_reply.err_desc = str;
//     // TODO: memory leak

//     return sendtx_reply;
// }

// /**
//  * @brief  lwsiot_send_tx_inner
//  * Send transaction
//  *
//  *
//  * @author gaochun
//  * @email  gaochun@dabank.io
//  * @date   2019/11/19 17:29:6
//  * @param  LwsClient *      lws_client -LWS client
//  * @param  Transaction *    tx         -transaction instance
//  * @return  LwsIoTError -return error code
//  */
// static int lws_send_tx_inner(Transaction *tx, uint16_t *nonce, unsigned char *data, size_t *size)
// {
//     unsigned char tx_data[4096];
//     size_t size_tx = tx_serialize(tx, tx_data);

//     struct SendTxReq req = create_sendtx_req(tx_data, size_tx);
//     *nonce = req.nonce;
//     *size = sendtx_req_serialize(&req, size_tx, data);

//     return 0;
// }

// // static void lws_restore_tx(Transaction *tx)
// // {
// //     struct UTXOIndex utxo_index;
// //     memcpy(utxo_index.txid, tx->input, 32);
// //     memcpy(&utxo_index.out, tx->input + 32, 1);

// //     int index = arraylist_index_of(G.utxo_list, equal_utxo, &utxo_index);
// //     struct UTXO *utxo = (struct UTXO *)G.utxo_list->data[index];

// //     utxo->is_used = 0; // set this utxo is unused
// // }

// /**
//  * @brief  lwsiot_tx_destroy
//  * Destroy a transaction instance
//  *
//  *
//  * @author gaochun
//  * @email  gaochun@dabank.io
//  * @date   2019/11/19 17:30:47
//  * @param  LwsClient *      lws_client -LWS client
//  * @param  Transaction *    tx         -transaction instance
//  * @return  void
//  */
// static void lws_tx_destroy(Transaction *tx)
// {
//     if (tx) {
//         if (tx->vch_data) {
//             free(tx->vch_data);
//         }

//         if (tx->input) {
//             free(tx->input);
//         }
//         free(tx);
//     }
// }

// int lws_protocol_init()
// {
//     //
//     if (NULL == G.fork_ctx) {
//         return -1;
//     }

//     G.fork_get(G.fork_ctx, G.fork);

//     //
//     if (NULL == G.public_key_ctx) {
//         return -2;
//     }

//     G.public_key_get(G.public_key_ctx, G.pk);

//     //
//     if (NULL == G.device_id_ctx) {
//         return -3;
//     }

//     G.device_id_get(G.device_id_ctx, G.id);

//     G.utxo_list = arraylist_new(0);

//     return 0;
// }

// size_t lws_service_request(unsigned char *data)
// {
//     struct ServiceReq service_req = create_service_req();
//     return service_req_serialize(&service_req, data);
// }

// int lws_service_reply_handle(const unsigned char *data, const size_t len, ServiceResult *result)
// {
//     if (NULL == result) {
//         return -1;
//     }

//     ServiceReply service_reply = service_reply_deserialize(data);

//     if (0 == service_reply.error && G.service_nonce == service_reply.nonce) {
//         result->nonce = service_reply.nonce;
//         result->version = service_reply.version;
//         result->address_id = service_reply.address_id;
//         memcpy(result->fork_bitmap, service_reply.fork_bitmap, 8);
//         memcpy(result->seed, service_reply.seed, 32);

//         // Set global
//         G.address_id = service_reply.address_id;
//         memcpy(G.fork_bitmap, service_reply.fork_bitmap, 8);
//         memcpy(G.seed, service_reply.seed, 32);
//     }

//     return service_reply.error;
// }

// size_t lws_sync_request(unsigned char *data)
// {
//     ServiceReply reply;
//     reply.address_id = G.address_id;
//     memcpy(reply.seed, G.seed, 32);

//     struct SyncReq sync_req = create_sync_req(&reply);

//     return sync_req_serialize(&sync_req, data);
// }

// int lws_sync_reply_handle(const unsigned char *data, const size_t len, SyncResult *result)
// {
//     if (NULL == result) {
//         return -1;
//     }

//     SyncReply sync_reply = sync_reply_deserialize(data);

//     if (G.sync_nonce == sync_reply.nonce) {
//         // 全局状态
//         memcpy(G.last_block_hash, sync_reply.block_hash, 32);
//         G.last_block_height = sync_reply.block_height;
//         G.last_block_time = sync_reply.block_time;

//         if (0 == sync_reply.error) {
//         } else if (1 == sync_reply.error) {
//             // clear globle utxo list
//             int i, len = G.utxo_list->length;
//             for (i = 0; i < len; i++) {
//                 struct UTXO *utxo = (struct UTXO *)G.utxo_list->data[i];
//                 if (!utxo && !utxo->data) {
//                     free(utxo->data);
//                     free(utxo);
//                 }
//             }

//             arraylist_clear(G.utxo_list);

//             len = sync_reply.utxo_list->length;

//             for (i = 0; i < len; i++) {
//                 struct UTXO *utxo = (struct UTXO *)sync_reply.utxo_list->data[i];
//                 utxo->is_used = 0;
//                 arraylist_append(G.utxo_list, utxo);
//             }

//             arraylist_sort(G.utxo_list, compare_utxo);

//             arraylist_clear(sync_reply.utxo_list);
//             arraylist_free(sync_reply.utxo_list);
//         } else {
//         }

//         // 返回值
//         result->nonce = sync_reply.nonce;
//         memcpy(result->block_hash, sync_reply.block_hash, 32);
//         result->block_height = sync_reply.block_height;
//         result->block_time = sync_reply.block_time;
//         result->utxo_num = sync_reply.utxo_num;
//         result->continue_flag = sync_reply.continue_flag;
//     }

//     return sync_reply.error;
// }

// size_t lws_send_tx_request(const char *address_hex, VchData *vch_data, unsigned char *data)
// {
//     ed25519_public_key address;
//     hex_to_uchar(address_hex, address);
//     reverse(address, 32);

//     Transaction *tx = lws_create_tx(address, vch_data);
//     if (!tx) {
//         return 0;
//     }

//     int rc = lws_sign_tx(tx);
//     if (0 != rc) {
//         lws_tx_destroy(tx);
//         return 0;
//     }

//     uint16_t nonce;
//     size_t size = 0;
//     rc = lws_send_tx_inner(tx, &nonce, data, &size);

//     lws_tx_destroy(tx);

//     return size;
// }

// int lws_send_tx_reply_handle(const unsigned char *data, const size_t len, SendTxResult *result)
// {
//     unsigned char buff[1024] = {'\0'};
//     memcpy(buff, data, len);
//     struct SendTxReply reply = sendtx_reply_deserialize(buff);

//     result->err_code = reply.err_code;
//     result->err_desc = reply.err_desc;
//     result->nonce = reply.nonce;
//     strcpy(result->txid, reply.txid);

//     if (reply.error != 0) {
//         arraylist_clear(G.utxo_list);
//         // lwsiot_sync((LwsClient *)ctx);
//         return reply.error;
//     }

//     int l = G.utxo_list->length;
//     for (int i = 0; i < l; i++) {
//         struct UTXO *item = (struct UTXO *)G.utxo_list->data[i];
//         if (item->is_used == 1) {
//             unsigned char buf[32] = {0};
//             hex_to_uchar(reply.txid, buf);
//             for (int j = 0; j < 32; j++) {
//                 item->txid[j] = buf[31 - j];
//             }
//             item->is_used = 0;
//             item->out = 0;
//             item->amount = item->new_amount;
//             break;
//         }
//     }

//     return reply.error;
// }

//------------------------------------------------------------------------

struct _LWSProtocol {
    uint32_t listunspent_index;
    uint32_t sendtx_index;
    LWSProtocolHook *hook;
    ArrayList *utxo_list;
    unsigned char last_block_hash[32];
    uint32_t last_block_height;
    uint32_t last_block_time;
};

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

static int check_endian()
{
    int a = 1;
    char *p = (char *)&a;

    return (*p == 1); /*1:little-endian, 0:big-endian*/
}

struct RequestHead {
    uint16_t version;
    uint8_t length;
    unsigned char *id;
    unsigned char hash[32];
};

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

    foot = protocol->hook->hook_crc32_get(protocol->hook->hook_fork_context, request, len - 4);
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

struct UTXO {
    unsigned char txid[32];
    uint8_t out;
    uint32_t block_height;
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

        size_thing = sizeof(utxo->block_height);
        deserialize_join(&size, data, &utxo->block_height, size_thing);

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
        reverse((unsigned char *)&utxo->out, 1);
        reverse((unsigned char *)&utxo->block_height, 4);
        reverse((unsigned char *)&utxo->type, 2);
        reverse((unsigned char *)&utxo->amount, 8);
        reverse((unsigned char *)&utxo->lock_until, 4);
        reverse((unsigned char *)&utxo->data_size, 2);

        arraylist_append(body.utxo_list, utxo);
    }

    return body;
}

LWSPError protocol_listunspent_reply_handle(LWSProtocol *protocol, const unsigned char *data, const size_t len)
{
    unsigned char out[len];
    size_t out_len = 0;
    LWSPError error = reply_remove_head(data, len, out, &out_len);
    if (LWSPError_Success == error) {
        struct ListUnspentBody body = listunspent_body_deserialize(out);

        // 全局状态
        memcpy(protocol->last_block_hash, body.block_hash, 32);
        protocol->last_block_height = body.block_height;
        protocol->last_block_time = body.block_time;

        // TODO:端序转化

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

static Transaction *transaction_new(LWSProtocol *protocol, const unsigned char *address, const VchData *vch_data)
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

static int transaction_hash(LWSProtocol *protocol, Transaction *tx, unsigned char *tx_id)
{
    unsigned char data[1024];
    size_t size = transaction_serialize_without_sign(tx, data);
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

LWSPError protocol_sendtx_request(LWSProtocol *protocol, const char *address, const VchData *vch, sha256_hash hash,
                                  unsigned char *data, size_t *length)
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

    // 创建send tx请求
    struct SendTxRequest request;
    request.nonce = protocol->hook->hook_nonce_get(protocol->hook->hook_nonce_context);
    transaction_hash(protocol, tx, request.tx_id);
    protocol->hook->hook_fork_get(protocol->hook->hook_fork_context, request.fork_id);
    request.data_size = tx_data_len;

    // 序列化send tx请求
    size_t body_len = 4 + 32 + 32 + 2 + tx_data_len + 2;
    unsigned char body[body_len];
    uint16_t command = SendTx;
    memcpy(body, &command, 2);
    memcpy(&body[2], &request, body_len - tx_data_len - 2);
    memcpy(&body[72], request.tx_id, tx_data_len);

    protocol->hook->hook_sha256_get(protocol->hook->hook_sha256_context, body, body_len, hash);

    // 生成请求
    wrap_request(protocol, body, body_len, hash, data, length);
    protocol->sendtx_index++;

    // 删除tx

    return LWSPError_Success;
}

LWSPError protocol_sendtx_reply_handle(LWSProtocol *protocol, const unsigned char *data, const size_t len)
{
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