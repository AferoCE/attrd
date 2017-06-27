/*
 * file attr_common.c -- implementation of client/server common code
 *
 * Copyright (c) 2016 Afero, Inc. All rights reserved.
 *
 */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "attr_prv.h"
#include "af_attr_client.h"
#include "af_rpc.h"
#include "af_log.h"

/* transaction API */

uint16_t sTransId = 1; // Valid transaction IDs can not be zero

uint16_t get_trans_id(void)
{
    uint16_t retVal = sTransId;
    sTransId++;
    if (sTransId == 0) {
        sTransId++;
    }
    return retVal;
}

static trans_context_t *sTransPool = NULL;
static trans_context_t *sTransFree = NULL;

/* allocate a pool of transactions */
int trans_pool_init(uint16_t maxTransactions)
{
    sTransPool = (trans_context_t *)calloc(maxTransactions, sizeof(trans_context_t));
    if (sTransPool == NULL) {
        errno = ENOMEM;
        return -1;
    }

    int i;
    for (i = 0; i < maxTransactions - 1; i++) {
        sTransPool[i].next = &sTransPool[i+1];
    }
    sTransPool[maxTransactions - 1].next = NULL;
    sTransFree = &sTransPool[0];
    return 0;
}

/* assumes no one is using any transactions */
void trans_pool_deinit(void)
{
    if (sTransPool) {
        sTransFree = NULL;
        free(sTransPool);
        sTransPool = NULL;
    }
}

/* get a transaction from the pool */
trans_context_t *trans_pool_alloc(void)
{
    trans_context_t *retVal = sTransFree;
    if (sTransFree) {
        sTransFree = sTransFree->next;
        memset (retVal, 0, sizeof(trans_context_t));
    }
    return retVal;
}

/* free a transaction to the pool */
void trans_pool_free(trans_context_t *trans)
{
    if (trans != NULL) {
        trans->next = sTransFree;
        sTransFree = trans;
    }
}

/* initialize RPC based on transaction */

typedef struct {
    uint8_t *value;
    uint32_t refCount;
} trans_mem_prv_t;

trans_mem_t *trans_mem_create(uint8_t *value)
{
    if (value == NULL) {
        errno = EINVAL;
        return NULL;
    }

    trans_mem_prv_t *retVal = (trans_mem_prv_t *)malloc(sizeof(trans_mem_prv_t));
    if (retVal == NULL) {
        return NULL;
    }
    retVal->value = value;
    retVal->refCount = 0;
    return (trans_mem_t *)retVal;
}

void trans_mem_inc_ref_count(trans_mem_t *mem)
{
    if (mem != NULL) {
        trans_mem_prv_t *tm = (trans_mem_prv_t *)mem;
        tm->refCount++;
        AFLOG_DEBUG3("reference count for %p is %d", mem, tm->refCount);
    }
}


void trans_mem_dec_ref_count(trans_mem_t *mem)
{
    if (mem != NULL) {
        trans_mem_prv_t *tm = (trans_mem_prv_t *)mem;
        tm->refCount--;
        AFLOG_DEBUG3("reference count for %p is %d", mem, tm->refCount);
        if (tm->refCount == 0) {
            free(tm->value);
            free(tm);
            AFLOG_DEBUG3("Freed trans_mem at %p", mem);
        }
    }
}

void *trans_mem_get_value(trans_mem_t *mem)
{
    if (mem == NULL) {
        return NULL;
    }

    trans_mem_prv_t *tm = (trans_mem_prv_t *)mem;
    return tm->value;
}


void trans_add(trans_context_t **head, trans_context_t *t)
{
    if (head != NULL) {
        /* add to list */
        t->next = *head;
        *head = t;
    }
}

trans_context_t *trans_find_transaction_with_id(trans_context_t **head, uint16_t id)
{
    if (head == NULL) {
        return NULL;
    }

    trans_context_t *trans;

    for (trans = *head; trans; trans = trans->next) {
        if (trans->transId == id) {
            return trans;
        }
    }
    return NULL;
}

int trans_remove(trans_context_t **head, trans_context_t *trans)
{
    if (head == NULL) {
        return -1;
    }

    trans_context_t *cur, *prev = NULL;
    for (cur = *head; cur; cur = cur->next) {
        if (cur == trans) {
            if (prev == NULL) {
                *head = cur->next;
            } else {
                prev->next = cur->next;
            }
            return 0;
        }
        prev = cur;
    }
    errno = ENOENT;
    return -1;
}


int trans_rpc_create_rpc_for_transmit(uint8_t *buf, int bufSize, trans_context_t *t)
{
    if (buf == NULL || t == NULL || bufSize <= 0) {
        AFLOG_ERR("create_rpc_for_xmit_param:buf_null=%d,t_null=%d,bufSize=%d:",
                  buf == NULL, t == NULL, bufSize);
        return AF_RPC_ERR_BAD_PARAM;
    }

    if (t->pos == t->size) {
        return 0; // zero length indicates we're done
    } else if (t->pos > t->size) {
        AFLOG_ERR("create_rpc_for_xmit_pos:pos=%d,size=%d:", t->pos, t->size);
        return AF_RPC_ERR_BAD_PARAM;
    }

    af_rpc_param_t params[7];
    AF_RPC_SET_PARAM_AS_UINT8(params[0], t->opcode);
    AF_RPC_SET_PARAM_AS_UINT16(params[1], t->transId);
    AF_RPC_SET_PARAM_AS_UINT16(params[2], t->opId);
    AF_RPC_SET_PARAM_AS_UINT32(params[3], t->attrId);
    AF_RPC_SET_PARAM_AS_UINT16(params[4], t->size);
    AF_RPC_SET_PARAM_AS_UINT16(params[5], t->pos);

    uint16_t bytesToSend = t->size - t->pos;
    if (bytesToSend > MAX_SEND_BLOB_SIZE) {
        bytesToSend = MAX_SEND_BLOB_SIZE;
    }

    /* if it's a set, the data is stored directly, otherwise it's reference counted */
    if (t->size > MAX_SIZE_FOR_INTERNAL_DATA) {
        if (t->opcode == AF_ATTR_OP_NOTIFY) {
            AF_RPC_SET_PARAM_AS_BLOB(params[6], trans_mem_get_value(t->u.dataP) + t->pos, bytesToSend);
        } else {
            AF_RPC_SET_PARAM_AS_BLOB(params[6], t->u.dataP + t->pos, bytesToSend);
        }
    } else {
        AF_RPC_SET_PARAM_AS_BLOB(params[6], t->u.data, bytesToSend);
    }

    AFLOG_DEBUG3("trans_rpc_create:pos=%d,bytesToSend=%d", t->pos, bytesToSend);
    int retVal = af_rpc_create_buffer_with_params(buf, bufSize, params, ARRAY_SIZE(params));
    t->pos += bytesToSend;

    return retVal;
}

int trans_rpc_create_rpc_for_receive(uint8_t *buf, int bufSize, uint8_t status, uint16_t transId)
{
    if (buf == NULL || bufSize <= 0) {
        AFLOG_ERR("create_rpc_for_rx_param:buf_null=%d,bufSize=%d:", buf == NULL, bufSize);
        return -1;
    }
    af_rpc_param_t params[2];
    AF_RPC_SET_PARAM_AS_UINT8(params[0], status);
    AF_RPC_SET_PARAM_AS_UINT16(params[1], transId);

    int retVal = af_rpc_create_buffer_with_params(buf, bufSize, params, ARRAY_SIZE(params));

    return retVal;
}

int trans_rpc_read_received_rpc(uint8_t *buf, int bufSize, trans_context_t *t, uint8_t **blob, uint16_t *blobSize)
{
    if (buf == NULL || bufSize <= 0 || t == NULL || blob == NULL || blobSize == NULL) {
        AFLOG_ERR("read_tx_rpc_param:buf_null=%d,bufSize=%d,t_null=%d,blob_null=%d,blobSize_null=%d:",
                  buf == NULL, bufSize, t == NULL, blob == NULL, blobSize == NULL);
        return AF_RPC_ERR_BAD_PARAM;
    }

    memset(t, 0, sizeof(trans_context_t));

    af_rpc_param_t params[7];
    params[0].type = AF_RPC_TYPE_UINT8;   // opcode
    params[1].type = AF_RPC_TYPE_UINT16;  // transId
    params[2].type = AF_RPC_TYPE_UINT16;  // opId
    params[3].type = AF_RPC_TYPE_UINT32;  // attrId
    params[4].type = AF_RPC_TYPE_UINT16;  // size
    params[5].type = AF_RPC_TYPE_UINT16;  // pos
    params[6].type = AF_RPC_TYPE_BLOB(0); // blob

    int status = af_rpc_get_params_from_buffer(params, ARRAY_SIZE(params), buf, bufSize, AF_RPC_STRICT);
    if (status < 0) {
        AFLOG_ERR("read_tx_rpc_opcode_status:status=%d:", status);
        return status;
    }

    t->opcode  = AF_RPC_GET_UINT8_PARAM(params[0]);
    t->transId = AF_RPC_GET_UINT16_PARAM(params[1]);
    t->opId    = AF_RPC_GET_UINT16_PARAM(params[2]);
    t->attrId  = AF_RPC_GET_UINT32_PARAM(params[3]);
    t->size    = AF_RPC_GET_UINT16_PARAM(params[4]);
    t->pos     = AF_RPC_GET_UINT16_PARAM(params[5]);

    *blob = params[6].base;
    *blobSize = AF_RPC_BLOB_SIZE(params[6].type);

    return 0;
}

#define TRANSACTION_TIMEOUT           (4000)

static void trans_cleanup_rx(trans_context_t **head, trans_context_t *t)
{
    if (t != NULL) {
        /* cancel the timer, if it exists */
        if (t->u2.rxc.timeoutEvent) {
            evtimer_del(t->u2.rxc.timeoutEvent);
            event_free(t->u2.rxc.timeoutEvent);
            t->u2.rxc.timeoutEvent = NULL;
        }

        /* remove the transaction from the list, if it's there */
        if (head != NULL) {
            trans_remove(head, t);
        }
        trans_cleanup(t);
    }
}


void trans_cleanup(trans_context_t *t)
{
    if (t != NULL) { /* we have a transaction context */
        /* free the memory associated with the transaction */
        if (t->size > MAX_SIZE_FOR_INTERNAL_DATA && t->u.dataP) {
            if (t->opcode == AF_ATTR_OP_NOTIFY) {
                trans_mem_dec_ref_count(t->u.dataP);
            } else {
                free(t->u.dataP);
            }
            t->u.dataP = NULL;
        }
        /* free the transaction */
        trans_pool_free(t);
    }
}


static void on_receive_timeout(evutil_socket_t fd, short what, void *arg)
{
    trans_context_t *trans = (trans_context_t *)arg;

    if (trans != NULL) {
        trans_cleanup_rx(trans->u2.rxc.head, trans);
    }
}


int trans_receive_packet(uint8_t *buf, int bufSize,
                         trans_context_t **trans, trans_context_t **head,
                         uint32_t seqNum,
                         struct event_base *base,
                         send_response_callback_t sendCB)
{
    trans_context_t tRead, *t = NULL;
    uint8_t *blob;
    uint16_t blobSize;
    uint8_t txBuf[32]; // for status message */
    int status, len;

    /* check parameters */
    if (buf == NULL || trans == NULL || head == NULL || sendCB == NULL || base == NULL || bufSize <= 0) {
        AFLOG_ERR("receive_packet_param:buf_null=%d,trans_null=%d,head_null=%d,sendCB_null=%d,base_null=%d,bufSize=%d",
                  buf == NULL, trans == NULL, head == NULL, sendCB == NULL, base == NULL, bufSize);
        status = AF_ATTR_STATUS_BAD_PARAM;
        goto exit;
    }

    /* unpack RPC message */
    status = trans_rpc_read_received_rpc(buf, bufSize, &tRead, &blob, &blobSize);
    if (status < 0) {
        AFLOG_ERR("handle_get_read_rpc:status=%d:", status);
        status = AF_ATTR_STATUS_BAD_TLV;
        goto exit;
    }

    status = AF_ATTR_STATUS_OK;

    /* check if this is a new message */
    if (tRead.transId == 0) {
        if (tRead.pos != 0) {
            AFLOG_ERR("handle_get_transId_pos:pos=%d:", tRead.pos);
            status = AF_ATTR_STATUS_BAD_DATA;
            goto exit;
        }
        /* allocate a new transaction */
        t = trans_pool_alloc();
        if (t == NULL) {
            AFLOG_ERR("handle_get_alloc_trans:: no get transaction context");
            status = AF_ATTR_STATUS_TOO_MANY_TRANSACTIONS;
            goto exit;
        }
        memcpy (t, &tRead, sizeof(tRead));

        /* check the size and position */
        if (t->pos + blobSize > t->size) {
            AFLOG_ERR("handle_get_overflow:pos=%d,blobSize=%d,size=%d:", t->pos, blobSize, t->size);
            status = AF_ATTR_STATUS_BAD_DATA;
            goto exit;
        }

        /* allocate a new transaction ID */
        t->transId = get_trans_id();

        /* allocate space if necessary and copy available data */
        if (t->size > MAX_SIZE_FOR_INTERNAL_DATA) {
            /* allocate space for the data */
            t->u.dataP = calloc(1, t->size);
            if (t->u.dataP == NULL) {
                AFLOG_ERR("handle_get_alloc_data::");
                trans_pool_free(t);
                status = AF_ATTR_STATUS_NO_SPACE;
                goto exit;
            }
            memcpy(t->u.dataP, blob, blobSize);
        } else {
            memcpy (t->u.data, blob, blobSize);
        }

        /* add this transaction to the list head */
        trans_add(head, t);

    } else { // This is an existing transaction
        /* find transaction */
        t = trans_find_transaction_with_id(head, tRead.transId);
        if (t == NULL) {
            AFLOG_ERR("handle_get_not_found:transId=%d:transaction not found", tRead.transId);
            status = AF_ATTR_STATUS_TRANSACTION_NOT_FOUND;
            goto exit;
        }
        /* check consistency */
        if (t->size != tRead.size || t->attrId != tRead.attrId) {
            AFLOG_ERR("handle_get_mismatch:t_size=%d,tRead_size=%d,t_attrId=%u,tRead_attrId=%d:",
                      t->size, tRead.size, t->attrId, tRead.attrId);
            status = AF_ATTR_STATUS_BAD_DATA;
            goto exit;
        }
        /* check for overflows */
        if (t->pos + blobSize > t->size) {
            AFLOG_ERR("handle_get_overflow:pos=%d,blobSize=%d,size=%d:", t->pos, blobSize, t->size);
            status = AF_ATTR_STATUS_BAD_DATA;
            goto exit;
        }
        /* grab the new data */
        memcpy(t->u.dataP + t->pos, blob, blobSize);
    }

    AFLOG_DEBUG3("trans_receive_packet:pos=%d,blobSize=%d", t->pos, blobSize);

    /* update the receive data position */
    t->pos += blobSize;

    /* check if we have received the last packet */
    if (t->pos > t->size) {
        /* transmitter sent too much data somehow */
        AFLOG_ERR("handle_get_overflow:pos=%d,size=%d:", t->pos, t->size);
        status = AF_ATTR_STATUS_BAD_DATA;
        goto exit;
    } else if (t->pos == t->size) {
        /* This is the last packet; remove from the pending receive list */
        trans_remove(head, t);

        /* remove the timeout event if we created one */
        if (t->u2.rxc.timeoutEvent != NULL) {
            evtimer_del(t->u2.rxc.timeoutEvent);
            event_free(t->u2.rxc.timeoutEvent);
            t->u2.rxc.timeoutEvent = NULL;
        }
    } else {
        /* check if we have a timer already */
        if (t->u2.rxc.timeoutEvent == NULL) {
            /* we did not have a timer; create one */
            t->u2.rxc.timeoutEvent = evtimer_new(base, on_receive_timeout, t);
            if (t->u2.rxc.timeoutEvent == NULL) {
                AFLOG_ERR("receive_packet_event_new::");
                status = AF_ATTR_STATUS_NO_SPACE;
                goto exit;
            }
        } else {
            /* we had a timer; cancel it */
            evtimer_del(t->u2.rxc.timeoutEvent);
        }

        /* add timeout event to clean up data if the transmitter stops talking */
        struct timeval tv;
        tv.tv_sec = TRANSACTION_TIMEOUT / 1000;
        tv.tv_usec = 1000 * (TRANSACTION_TIMEOUT % 1000);
        evtimer_add(t->u2.rxc.timeoutEvent, &tv);
    }

exit:
    /* if an error occurred, clean up allocated resources */
    if (status != 0) {
        trans_cleanup_rx(head, t);
        t = NULL;
    }

    /* send a response message */
    len = trans_rpc_create_rpc_for_receive(txBuf, sizeof(txBuf), (uint8_t)status, t == NULL ? 0 : t->transId);
    if (len < 0) {
        AFLOG_ERR("handle_get_create_rpc:len=%d:", len);
    } else {
        if ((sendCB)(seqNum, txBuf, len) < 0) {
            AFLOG_ERR("handle_get_send_response:errno=%d:", errno);
        }
    }

    *trans = t;
    return status;
}

static int trans_transmit_internal (trans_context_t *trans);

void on_transmit_response(int status, uint32_t seqNum, uint8_t *rxBuf, int rxBufSize, void *context)
{
    trans_context_t *t = (trans_context_t *)context;

    /* check params */
    if (t == NULL) {
        AFLOG_ERR("on_trans_tx_resp_t_null::");
        return;
    }

    /* check status of send */
    if (status != 0) {
        AFLOG_ERR("on_trans_tx_resp_status:status=%d:transaction request failed", status);
        goto exit;
    }

    if (rxBuf == NULL || rxBufSize <= 0) {
        AFLOG_ERR("on_trans_tx_resp_param:rxBuf_null=%d,rxBufSize=%d", rxBuf == NULL, rxBufSize);
        status = AF_ATTR_STATUS_BAD_PARAM;
        goto exit;
    }

    /* read response message */
    af_rpc_param_t params[2] = { { NULL, AF_RPC_TYPE_UINT8 } , { NULL, AF_RPC_TYPE_UINT16 } };
    status = af_rpc_get_params_from_buffer(params, ARRAY_SIZE(params), rxBuf, rxBufSize, AF_RPC_STRICT);

    if (status < 0) {
        AFLOG_ERR("on_trans_tx_resp_params:status=%d:unable to parse response", status);
        status = AF_ATTR_STATUS_UNSPECIFIED;
        goto exit;
    }

    /* check status from receiver */
    uint8_t iStatus = AF_RPC_GET_UINT8_PARAM(params[0]);
    if (iStatus != 0) {
        AFLOG_ERR("on_trans_tx_resp_istatus:iStatus=%d:", iStatus);
        status = iStatus;
        goto exit;
    }

    /* all iz well; send next packet */
    if (t->pos < t->size) {
        t->transId = AF_RPC_GET_UINT16_PARAM(params[1]);
        status = trans_transmit_internal(t);
        if (status != 0) {
            AFLOG_ERR("on_trans_tx_resp_transmit: status=%d", status);
            /* clean up */
            goto exit;
        }
        /* we're now waiting for another response so don't call finished callback */
        return;
    }
    /* we're done with all packets */
    status = AF_ATTR_STATUS_OK;

exit:
    if (t->u2.txc.finishedCB != NULL) {
        (t->u2.txc.finishedCB) (status, t, t->u2.txc.finishedContext);
    }
}

/* we assume that the transaction structure is filled in correctly for transmit */
/* This function does NOT call the finish callback if the transmission fails */
static int trans_transmit_internal (trans_context_t *trans)
{
    uint8_t txBuf[AF_IPC_MAX_MSGLEN];
    int len = trans_rpc_create_rpc_for_transmit(txBuf, sizeof(txBuf), trans);

    if (len == 0) {
        return AF_ATTR_STATUS_OK;
    } else if (len < 0) {
        AFLOG_ERR("trans_transmit_len:len=%d:", len);
        return AF_ATTR_STATUS_UNSPECIFIED;
    }

    if (trans->u2.txc.sendCB != NULL) {
        if ((trans->u2.txc.sendCB)(trans->u2.txc.clientId, txBuf, len, on_transmit_response, trans, TRANSACTION_TIMEOUT) < 0) {
            AFLOG_ERR("trans_transmit_send:errno=%d:", errno);
            return AF_ATTR_STATUS_UNSPECIFIED;
        }
        /* if this is a notification, increase the reference count */
        if (trans->opcode == AF_ATTR_OP_NOTIFY) {
            if (trans->size > MAX_SIZE_FOR_INTERNAL_DATA) {
                trans_mem_inc_ref_count(trans->u.dataP);
            }
        }
    }

    return AF_ATTR_STATUS_OK;
}

int trans_transmit(uint16_t clientId, trans_context_t *trans, send_request_callback_t sendCB,
                   finished_callback_t finishedCB, void *finishedContext)
{
    if (trans == NULL ||  sendCB == NULL) {
        AFLOG_ERR("trans_transmit_param:trans_null=%d,sendCB_null=%d", trans == NULL, sendCB == NULL);
        return AF_ATTR_STATUS_BAD_PARAM;
    }

    trans->u2.txc.clientId = clientId;
    trans->u2.txc.sendCB = sendCB;
    trans->u2.txc.finishedCB = finishedCB;
    trans->u2.txc.finishedContext = finishedContext;
    trans->transId = 0; /* initialize the transmit Id */

    int status = trans_transmit_internal(trans);

    /* clean up if transmit failed */
    if (status != 0) {
        if (trans->u2.txc.finishedCB != NULL) {
            (trans->u2.txc.finishedCB)(status, trans, trans->u2.txc.finishedContext);
        }
    }
    return status;
}

trans_context_t *trans_alloc (uint32_t attributeId, uint8_t opcode, uint8_t *value, int length)
{
    trans_context_t *t;

    if (length <= 0 || length > UINT16_MAX || value == NULL) {
        AFLOG_ERR("af_attr_set_param:length=%d,value_null=%d", length, value == NULL);
        return NULL;
    }

    t = trans_pool_alloc();
    if (t == NULL) {
        AFLOG_ERR("af_attr_set_alloc::");
        return NULL;
    }

    t->opcode = opcode;
    t->size = length;
    t->attrId = attributeId;

    /* allocate space if necessary and copy available data */
    if (t->size > MAX_SIZE_FOR_INTERNAL_DATA) {
        /* allocate space for the data */
        t->u.dataP = calloc(1, t->size);
        if (t->u.dataP == NULL) {
            AFLOG_ERR("handle_get_alloc_data::");
            trans_pool_free(t);
            return NULL;
        }
        memcpy(t->u.dataP, value, length);
    } else {
        memcpy(t->u.data, value, length);
    }

    return t;
}


static uint16_t sGetId = 1;
static uint16_t get_op_id(void)
{
    uint16_t retVal = sGetId;
    sGetId++;
    if (sGetId == 0) {
        sGetId++;
    }
    return retVal;
}

static op_context_t *sOpPool = NULL;
static op_context_t *sOpFree = NULL;

/* allocate a pool of transactions */
int op_pool_init(uint16_t maxOps)
{
    sOpPool = (op_context_t *)calloc(maxOps, sizeof(op_context_t));
    if (sOpPool == NULL) {
        errno = ENOMEM;
        return -1;
    }

    int i;
    for (i = 0; i < maxOps - 1; i++) {
        sOpPool[i].next = &sOpPool[i+1];
    }
    sOpPool[maxOps - 1].next = NULL;
    sOpFree = &sOpPool[0];
    return 0;
}

/* assumes no one is using any transactions */
void op_pool_deinit(void)
{
    if (sOpPool) {
        sOpFree = NULL;
        free(sOpPool);
        sOpPool = NULL;
    }
}

/* get a clean op context from the pool */
op_context_t *op_pool_alloc(void)
{
    op_context_t *retVal = sOpFree;
    if (sOpFree) {
        sOpFree = sOpFree->next;
        memset (retVal, 0, sizeof(op_context_t));
        retVal->opId = get_op_id();
        AFLOG_DEBUG2("allocated op:opId=%d", retVal->opId);
    }
    return retVal;
}

/* free a transaction to the pool */
void op_pool_free(op_context_t *o)
{
    if (o != NULL) {
        AFLOG_DEBUG2("freeing op:opId=%d", o->opId);
        o->next = sOpFree;
        sOpFree = o;
    }
}

int get_create_rpc(op_context_t *g, uint32_t attrId, uint8_t *buf, int bufSize)
{
    if (g == NULL || buf == NULL || bufSize <= 0) {
        AFLOG_ERR("get_create_rpc_param:g_null=%d,buf_null=%d,bufSize=%d",
                  g == NULL, buf == NULL, bufSize);
        return AF_ATTR_STATUS_BAD_PARAM;
    }

    af_rpc_param_t params[3];
    AF_RPC_SET_PARAM_AS_UINT8(params[0], AF_ATTR_OP_GET);
    AF_RPC_SET_PARAM_AS_UINT32(params[1], attrId);
    AF_RPC_SET_PARAM_AS_UINT16(params[2], g->opId);

    return af_rpc_create_buffer_with_params(buf, bufSize, params, ARRAY_SIZE(params));
}

int set_reply_create_rpc(uint8_t status, uint16_t setId, uint8_t *buf, int bufSize)
{
    if (buf == NULL || bufSize <= 0) {
        AFLOG_ERR("set_reply_create_rpc_param:buf_null=%d,bufSize=%d", buf == NULL, bufSize);
        return AF_ATTR_STATUS_BAD_PARAM;
    }

    af_rpc_param_t params[3];
    AF_RPC_SET_PARAM_AS_UINT8(params[0], AF_ATTR_OP_SET_REPLY);
    AF_RPC_SET_PARAM_AS_UINT8(params[1], status);
    AF_RPC_SET_PARAM_AS_UINT16(params[2], setId);
    return af_rpc_create_buffer_with_params(buf, bufSize, params, ARRAY_SIZE(params));
}


/* we actually don't care about the return value */
static int op_remove(op_context_t **head, op_context_t *g)
{
    if (head == NULL) {
        return -1;
    }

    op_context_t *cur, *prev = NULL;
    for (cur = *head; cur; cur = cur->next) {
        if (cur == g) {
            if (prev == NULL) {
                *head = cur->next;
            } else {
                prev->next = cur->next;
            }
            return 0;
        }
        prev = cur;
    }
    return -1;
}

void op_cleanup(op_context_t **head, op_context_t *o)
{
    if (o != NULL) {
        uint16_t getId = o->opId;

        /* cancel the timer, if it exists */
        if (o->timeoutEvent) {
            evtimer_del(o->timeoutEvent);
            event_free(o->timeoutEvent);
            o->timeoutEvent = NULL;
            AFLOG_DEBUG3("removed_timer:opId=%d", getId);
        }

        /* remove the get from the list, if it's there */
        if (head != NULL) {
            op_remove(head, o);
            AFLOG_DEBUG3("removed_op:opId=%d", getId);
        }
        op_pool_free(o);
    }
}

op_context_t *op_find(op_context_t *head, uint16_t opId)
{
    op_context_t *o;
    for (o = head; o; o = o->next) {
        if (o->opId == opId) {
            break;
        }
    }
    return o;
}

struct event *allocate_and_add_timer(struct event_base *b, int timeoutMs, event_callback_t cb, void *context)
{
    struct event *e = NULL;
    if (b == NULL || cb == NULL) {
        AFLOG_ERR("allocate_and_add_timer_param:b_null=%d,cb_null=%d:", b == NULL, cb == NULL);
        return NULL;
    }

    e = evtimer_new(b, cb, context);
    if (e == NULL) {
        AFLOG_ERR("allocate_and_add_timer_new:errno=%d:can't get timer", errno);
        return NULL;
    }
    struct timeval tv;
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec =  1000 * (timeoutMs - tv.tv_sec * 1000);
    evtimer_add(e, &tv);

    return e;
}
