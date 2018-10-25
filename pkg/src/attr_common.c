/*
 * attr_common.c -- implementation of client/server common code
 *
 * Copyright (c) 2016-2018 Afero, Inc. All rights reserved.
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
#include "af_mempool.h"

/* attribute value API */
attr_value_t *attr_value_create(uint32_t attributeId, uint16_t size)
{
    attr_value_t *retVal = (attr_value_t *)calloc(1, size + sizeof(attr_value_t));
    if (retVal == NULL) {
        return NULL;
    }
    retVal->refCount = 1;
    retVal->size = size;
    retVal->attrId = attributeId;
    retVal->value = ((uint8_t *)retVal) + sizeof(attr_value_t);
    return retVal;
}

attr_value_t *attr_value_create_with_value(uint32_t attributeId, uint8_t *value, uint16_t size)
{
    attr_value_t *av = attr_value_create(attributeId, size);
    if (av) {
        if (value && size) {
            memcpy(av->value, value, size);
        }
    }
    return av;
}

void attr_value_inc_ref_count(attr_value_t *aValue)
{
    if (aValue != NULL) {
        aValue->refCount++;
        AFLOG_DEBUG3("attr_value_inc_ref:attrValueP=%p,count=%d", aValue, aValue->refCount);
    }
}

void attr_value_dec_ref_count(attr_value_t *aValue)
{
    if (aValue != NULL) {
        if (aValue->refCount == 0) {
            AFLOG_ERR("attr_value_ref_0:attrValueP=%p,refcount=0", aValue);
            return;
        }
        aValue->refCount--;
        AFLOG_DEBUG3("attr_value_dec_ref:attrValueP=%p,count=%d", aValue, aValue->refCount);
        if (aValue->refCount == 0) {
            free(aValue);
            AFLOG_DEBUG3("Freed attr_value at %p", aValue);
        }
    }
}

/* transaction API */

static uint16_t sTransId = 1; // Valid transaction IDs can not be zero

static uint16_t trans_new_id(void)
{
    uint16_t retVal = sTransId;
    sTransId++;
    if (sTransId == 0) {
        sTransId++;
    }
    return retVal;
}

static af_mempool_t *sTransPool = NULL;

/* allocate a pool of transactions */
int trans_pool_init(uint16_t maxTransactions)
{
    sTransPool = af_mempool_create(maxTransactions, sizeof(trans_context_t), AF_MEMPOOL_FLAG_EXPAND);
    if (sTransPool == NULL) {
        errno = ENOMEM;
        return -1;
    }
    return 0;
}

/* assumes no one is using any transactions */
void trans_pool_deinit(void)
{
    if (sTransPool) {
        af_mempool_destroy(sTransPool);
        sTransPool = NULL;
    }
}

/* get a transaction from the pool */
trans_context_t *trans_pool_alloc(void)
{
    trans_context_t *retVal = af_mempool_alloc(sTransPool);
    if (retVal) {
        memset (retVal, 0, sizeof(trans_context_t));
    }
    return retVal;
}

/* free a transaction to the pool */
void trans_pool_free(trans_context_t *trans)
{
    if (trans != NULL) {
        af_mempool_free(trans);
    }
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


static int trans_rpc_create_rpc_for_transmit(uint8_t *buf, int bufSize, trans_context_t *t)
{
    if (buf == NULL || t == NULL || bufSize <= 0) {
        AFLOG_ERR("create_rpc_for_xmit_param:buf_null=%d,t_null=%d,bufSize=%d:",
                  buf == NULL, t == NULL, bufSize);
        return AF_RPC_ERR_BAD_PARAM;
    }

    if (t->pos > t->attrValue->size) {
        AFLOG_ERR("create_rpc_for_xmit_pos:pos=%d,size=%d:", t->pos, t->attrValue->size);
        return AF_RPC_ERR_BAD_PARAM;
    }

    af_rpc_param_t params[7];
    AF_RPC_SET_PARAM_AS_UINT8(params[0], t->opcode);
    AF_RPC_SET_PARAM_AS_UINT16(params[1], t->transId);
    AF_RPC_SET_PARAM_AS_UINT16(params[2], t->opId);
    AF_RPC_SET_PARAM_AS_UINT32(params[3], t->attrValue->attrId);
    AF_RPC_SET_PARAM_AS_UINT16(params[4], t->attrValue->size);
    AF_RPC_SET_PARAM_AS_UINT16(params[5], t->pos);

    uint16_t bytesToSend = t->attrValue->size - t->pos;
    if (bytesToSend > MAX_SEND_BLOB_SIZE) {
        bytesToSend = MAX_SEND_BLOB_SIZE;
    }

    /* if it's a set, the data is stored directly, otherwise it's reference counted */
    AF_RPC_SET_PARAM_AS_BLOB(params[6], t->attrValue->value + t->pos, bytesToSend);

    AFLOG_DEBUG3("trans_rpc_create:pos=%d,bytesToSend=%d", t->pos, bytesToSend);
    int retVal = af_rpc_create_buffer_with_params(buf, bufSize, params, ARRAY_SIZE(params));
    t->pos += bytesToSend;

    return retVal;
}

static int trans_rpc_create_rpc_for_receive(uint8_t *buf, int bufSize, uint8_t status, uint16_t transId)
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

#define TRANSACTION_TIMEOUT           (4000)

static void trans_cleanup_rx(trans_context_t **head, trans_context_t *t)
{
    if (t != NULL) {
        /* cancel the timer, if it exists */
        if (t->u.rxc.timeoutEvent) {
            evtimer_del(t->u.rxc.timeoutEvent);
            event_free(t->u.rxc.timeoutEvent);
            t->u.rxc.timeoutEvent = NULL;
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
        /* decrement the ref count for the attribute value */
        attr_value_dec_ref_count(t->attrValue);

        /* free the transaction */
        trans_pool_free(t);
    }
}


static void on_receive_timeout(evutil_socket_t fd, short what, void *arg)
{
    trans_context_t *trans = (trans_context_t *)arg;

    if (trans != NULL) {
        trans_cleanup_rx(trans->u.rxc.head, trans);
    }
}


int trans_receive_packet(uint8_t *buf, int bufSize,
                         trans_context_t **trans, trans_context_t **head,
                         uint32_t seqNum,
                         struct event_base *base,
                         send_response_callback_t sendCB)
{
    trans_context_t *t = NULL;
    attr_value_t *a = NULL;
    uint8_t txBuf[32]; // for status message */
    uint16_t transId = 0;
    int status, len;

    /* check parameters */
    if (buf == NULL || trans == NULL || head == NULL || sendCB == NULL || base == NULL || bufSize <= 0) {
        AFLOG_ERR("receive_packet_param:buf_null=%d,trans_null=%d,head_null=%d,sendCB_null=%d,base_null=%d,bufSize=%d",
                  buf == NULL, trans == NULL, head == NULL, sendCB == NULL, base == NULL, bufSize);
        status = AF_ATTR_STATUS_BAD_PARAM;
        goto exit;
    }

    /* unpack RPC message */
    af_rpc_param_t params[7];
    params[0].type = AF_RPC_TYPE_UINT8;   // opcode
    params[1].type = AF_RPC_TYPE_UINT16;  // transId
    params[2].type = AF_RPC_TYPE_UINT16;  // opId
    params[3].type = AF_RPC_TYPE_UINT32;  // attrId
    params[4].type = AF_RPC_TYPE_UINT16;  // size
    params[5].type = AF_RPC_TYPE_UINT16;  // pos
    params[6].type = AF_RPC_TYPE_BLOB(0); // blob

    status = af_rpc_get_params_from_buffer(params, ARRAY_SIZE(params), buf, bufSize, AF_RPC_STRICT);
    if (status < 0) {
        AFLOG_ERR("trans_receive_rpc:status=%d:", status);
        status = AF_ATTR_STATUS_BAD_TLV;
        goto exit;
    }

    uint8_t opcode  = AF_RPC_GET_UINT8_PARAM(params[0]);
    transId = AF_RPC_GET_UINT16_PARAM(params[1]);
    uint16_t opId    = AF_RPC_GET_UINT16_PARAM(params[2]);
    uint32_t attrId  = AF_RPC_GET_UINT32_PARAM(params[3]);
    uint16_t size    = AF_RPC_GET_UINT16_PARAM(params[4]);
    uint16_t pos     = AF_RPC_GET_UINT16_PARAM(params[5]);
    uint8_t *blob = params[6].base;
    uint16_t blobSize = AF_RPC_BLOB_SIZE(params[6].type);

    status = AF_ATTR_STATUS_OK;

    if (transId == 0) {
        /* this is a new transaction */
        /* check if incoming data makes sense */
        if (pos != 0) {
            AFLOG_ERR("trans_receive:transId=0,pos=%d:", pos);
            status = AF_ATTR_STATUS_BAD_DATA;
            goto exit;
        }
        if (pos + blobSize > size) {
            AFLOG_ERR("trans_receive::pos=%d,blobSize=%d,size=%d:", pos, blobSize, size);
            status = AF_ATTR_STATUS_BAD_DATA;
            goto exit;
        }

        /* allocate a new transaction and attribute value object */
        t = trans_pool_alloc();
        if (t == NULL) {
            AFLOG_ERR("trans_receive_trans_pool_alloc::unable to alloc transaction context");
            status = AF_ATTR_STATUS_TOO_MANY_TRANSACTIONS;
            goto exit;
        }
        a = attr_value_create(attrId, size);
        if (a == NULL) {
            AFLOG_ERR("trans_receive_attr_value_create::unable to create attribute value");
            status = AF_ATTR_STATUS_TOO_MANY_TRANSACTIONS;
            goto exit;
        }
        t->attrValue = a; /* so it will get cleaned up correctly */
        t->opcode = opcode;
        t->transId = trans_new_id();
        t->opId = opId;
        t->pos = pos;
        if (blobSize) {
            memcpy(t->attrValue->value, blob, blobSize);
        }

        /* add this transaction to the list head */
        trans_add(head, t);

    } else {
        /* this is an existing transaction */
        /* find transaction */
        t = trans_find_transaction_with_id(head, transId);
        if (t == NULL) {
            AFLOG_ERR("handle_get_not_found:transId=%d:transaction not found", transId);
            status = AF_ATTR_STATUS_TRANSACTION_NOT_FOUND;
            goto exit;
        }
        /* check consistency */
        if (t->attrValue->size != size || t->attrValue->attrId != attrId) {
            AFLOG_ERR("handle_get_mismatch:t_size=%d,size=%d,t_attrId=%u,attrId=%d:",
                      t->attrValue->size, size, t->attrValue->attrId, attrId);
            status = AF_ATTR_STATUS_BAD_DATA;
            goto exit;
        }
        /* check for overflows */
        if (t->pos + blobSize > t->attrValue->size) {
            AFLOG_ERR("handle_get_overflow:pos=%d,blobSize=%d,size=%d:", t->pos, blobSize, t->attrValue->size);
            status = AF_ATTR_STATUS_BAD_DATA;
            goto exit;
        }
        /* grab the new data; blobSize cannot be zero */
        memcpy(t->attrValue->value + t->pos, blob, blobSize);
    }

    AFLOG_DEBUG3("trans_receive_packet:pos=%d,blobSize=%d", t->pos, blobSize);

    /* update the receive data position */
    t->pos += blobSize;

    /* check if we have received the last packet */
    if (t->pos > t->attrValue->size) {
        /* transmitter sent too much data somehow */
        AFLOG_ERR("handle_get_overflow:pos=%d,size=%d:", t->pos, t->attrValue->size);
        status = AF_ATTR_STATUS_BAD_DATA;
        goto exit;
    } else if (t->pos == t->attrValue->size) {
        /* This is the last packet; remove from the pending receive list */
        trans_remove(head, t);

        /* remove the timeout event if we created one */
        if (t->u.rxc.timeoutEvent != NULL) {
            evtimer_del(t->u.rxc.timeoutEvent);
            event_free(t->u.rxc.timeoutEvent);
            t->u.rxc.timeoutEvent = NULL;
        }
    } else {
        /* check if we have a timer already */
        if (t->u.rxc.timeoutEvent == NULL) {
            /* we did not have a timer; create one */
            t->u.rxc.timeoutEvent = evtimer_new(base, on_receive_timeout, t);
            if (t->u.rxc.timeoutEvent == NULL) {
                AFLOG_ERR("receive_packet_event_new::");
                status = AF_ATTR_STATUS_NO_SPACE;
                goto exit;
            }
        } else {
            /* we had a timer; cancel it */
            evtimer_del(t->u.rxc.timeoutEvent);
        }

        /* give the callback the head so transaction can be removed */
        t->u.rxc.head = head;

        /* add timeout event to clean up data if the transmitter stops talking */
        struct timeval tv;
        tv.tv_sec = TRANSACTION_TIMEOUT / 1000;
        tv.tv_usec = 1000 * (TRANSACTION_TIMEOUT % 1000);
        evtimer_add(t->u.rxc.timeoutEvent, &tv);
    }

exit:
    /* if an error occurred, clean up allocated resources */
    if (status != AF_ATTR_STATUS_OK) {
        trans_cleanup_rx(head, t);
    } else {
        *trans = t;
    }

    /* send a response message */
    len = trans_rpc_create_rpc_for_receive(txBuf, sizeof(txBuf), (uint8_t)status, status == AF_ATTR_STATUS_OK ? t->transId : 0);
    if (len < 0) {
        AFLOG_ERR("handle_get_create_rpc:len=%d:", len);
    } else {
        if ((sendCB)(seqNum, txBuf, len) < 0) {
            AFLOG_ERR("handle_get_send_response:errno=%d:", errno);
        }
    }

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
    if (status != AF_IPC_STATUS_OK) {
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
    if (iStatus != AF_ATTR_STATUS_OK) {
        AFLOG_ERR("on_trans_tx_resp_istatus:iStatus=%d:", iStatus);
        status = iStatus;
        goto exit;
    }

    /* all iz well; send next packet */
    if (t->pos < t->attrValue->size) {
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
    if (t->u.txc.finishedCB != NULL) {
        (t->u.txc.finishedCB) (status, t, t->u.txc.finishedContext);
    }
}

/* we assume that the transaction structure is filled in correctly for transmit */
/* This function does NOT call the finish callback if the transmission fails */
static int trans_transmit_internal (trans_context_t *trans)
{
    uint8_t txBuf[AF_IPC_MAX_MSGLEN];
    int len = trans_rpc_create_rpc_for_transmit(txBuf, sizeof(txBuf), trans);

    if (len < 0) {
        AFLOG_ERR("trans_transmit_len:len=%d:", len);
        return AF_ATTR_STATUS_UNSPECIFIED;
    }

    if (trans->u.txc.sendCB != NULL) {
        if ((trans->u.txc.sendCB)(trans->u.txc.clientId, txBuf, len, on_transmit_response, trans, TRANSACTION_TIMEOUT) < 0) {
            AFLOG_ERR("trans_transmit_send:errno=%d:", errno);
            return AF_ATTR_STATUS_UNSPECIFIED;
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

    trans->u.txc.clientId = clientId;
    trans->u.txc.sendCB = sendCB;
    trans->u.txc.finishedCB = finishedCB;
    trans->u.txc.finishedContext = finishedContext;
    trans->transId = 0; /* initialize the transmit Id */

    int status = trans_transmit_internal(trans);

    /* clean up if transmit failed */
    if (status != 0) {
        if (trans->u.txc.finishedCB != NULL) {
            (trans->u.txc.finishedCB)(status, trans, trans->u.txc.finishedContext);
        }
    }
    return status;
}

trans_context_t *trans_alloc (uint32_t attributeId, uint8_t opcode, uint8_t *value, int length)
{
    trans_context_t *t = NULL;
    attr_value_t *a = NULL;

    if (length < 0 || length > UINT16_MAX) {
        AFLOG_ERR("%s_param:length=%d", __func__, length);
        return NULL;
    }
    if (length > 0 && value == NULL) {
        AFLOG_ERR("%s_param:length=%d,value=NULL", __func__, length);
        return NULL;
    }

    t = trans_pool_alloc();
    if (t == NULL) {
        AFLOG_ERR("trans_alloc_trans:");
        return NULL;
    }

    a = attr_value_create_with_value(attributeId, value, length);
    if (a == NULL) {
        AFLOG_ERR("trans_alloc_attr_value:");
        trans_pool_free(t);
        return NULL;
    }

    t->opcode = opcode;
    t->attrValue = a;

    return t;
}


static uint16_t sGetId = 1;
static uint16_t op_new_id(void)
{
    uint16_t retVal = sGetId;
    sGetId++;
    if (sGetId == 0) {
        sGetId++;
    }
    return retVal;
}

static af_mempool_t *sOpPool = NULL;

/* allocate a pool of transactions */
int op_pool_init(uint16_t maxOps)
{
    sOpPool = af_mempool_create(maxOps, sizeof(op_context_t), AF_MEMPOOL_FLAG_EXPAND);
    if (sOpPool == NULL) {
        errno = ENOMEM;
        return -1;
    }
    return 0;
}

/* assumes no one is using any transactions */
void op_pool_deinit(void)
{
    af_mempool_destroy(sOpPool);
    sOpPool = NULL;
}

/* get a clean op context from the pool */
op_context_t *op_pool_alloc(void)
{
    op_context_t *retVal = af_mempool_alloc(sOpPool);
    if (retVal) {
        memset (retVal, 0, sizeof(op_context_t));
        retVal->opId = op_new_id();
        AFLOG_DEBUG3("allocated op:opId=%d", retVal->opId);
    }
    return retVal;
}

/* free a transaction to the pool */
void op_pool_free(op_context_t *o)
{
    if (o != NULL) {
        AFLOG_DEBUG3("freeing op:opId=%d", o->opId);
        af_mempool_free(o);
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
        /* cancel the timer, if it exists */
        if (o->timeoutEvent) {
            evtimer_del(o->timeoutEvent);
            event_free(o->timeoutEvent);
            o->timeoutEvent = NULL;
            AFLOG_DEBUG3("removed_timer:opId=%d", o->opId);
        }

        /* remove the get from the list, if it's there */
        if (head != NULL) {
            op_remove(head, o);
            AFLOG_DEBUG3("removed_op:opId=%d", o->opId);
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

op_context_t *op_alloc_with_timeout(struct event_base *b, uint16_t timeoutSec, event_callback_t cb)
{
    op_context_t *o = NULL;

    /* check parameters */
    if (b == NULL || cb == NULL) {
        AFLOG_ERR("op_alloc_with_timer_param:b_NULL=%d,cb_NULL=%d", b == NULL, cb == NULL);
        return NULL;
    }

    /* allocate the op */
    o = op_pool_alloc();
    if (o == NULL) {
        AFLOG_ERR("op_alloc_with_timer_alloc");
        return NULL;
    }

    /* allocate the timer */
    o->timeout = timeoutSec;
    o->timeoutEvent = allocate_and_add_timer(b, timeoutSec * 1000, cb, (void *)(uint32_t)o->opId);
    if (o->timeoutEvent == NULL) {
        op_pool_free(o);
        o = NULL;
    }
    return o;
}

/***************************************************************************************************************
 * Code to store and retrieve attributes in Little Endian
 */
void af_attr_store_uint16(uint8_t *dst, uint16_t value)
{
    if (dst == NULL) {
        return;
    }

    *dst++ = value & 0xff;
    *dst++ = value >> 8;
}

uint16_t af_attr_get_uint16(uint8_t *src)
{
    if (src == NULL) {
        return 0;
    }

    return src[0] | (src[1] << 8);
}

void af_attr_store_int16(uint8_t *dst, int16_t value)
{
    if (dst == NULL) {
        return;
    }

    uint16_t valueU = *(uint16_t *)&value;
    *dst++ = valueU & 0xff;
    *dst++ = valueU >> 8;
}

int16_t af_attr_get_int16(uint8_t *src)
{
    if (src == NULL) {
        return 0;
    }

    uint16_t valueU = src[0] | (src[1] << 8);
    return *(int16_t *)&valueU;
}

void af_attr_store_uint32(uint8_t *dst, uint32_t value)
{
    if (dst == NULL) {
        return;
    }

    *dst++ = value & 0xff;
    *dst++ = (value & 0xff00) >> 8;
    *dst++ = (value & 0xff0000) >> 16;
    *dst++ = value >> 24;
}

uint32_t af_attr_get_uint32(uint8_t *src)
{
    if (src == NULL) {
        return 0;
    }

    return src[0] | (src[1] << 8) | (src[2] << 16) | (src[3] << 24);
}

void af_attr_store_int32(uint8_t *dst, int32_t value)
{
    if (dst == NULL) {
        return;
    }

    uint32_t valueU = *(uint32_t *)&value;
    *dst++ = valueU & 0xff;
    *dst++ = (valueU & 0xff00) >> 8;
    *dst++ = (valueU & 0xff0000) >> 16;
    *dst++ = valueU >> 24;
}

int32_t af_attr_get_int32(uint8_t *src)
{
    if (src == NULL) {
        return 0;
    }

    uint32_t valueU = src[0] | (src[1] << 8) | (src[2] << 16) | (src[3] << 24);
    return *(int32_t *)&valueU;
}

void af_attr_store_uint64(uint8_t *dst, uint64_t value)
{
    if (dst == NULL) {
        return;
    }

    *dst++ = value & 0xff;
    *dst++ = (value & 0xff00) >> 8;
    *dst++ = (value & 0xff0000) >> 16;
    *dst++ = (value & 0xff000000) >> 24;
    *dst++ = (value & 0xff00000000) >> 32;
    *dst++ = (value & 0xff0000000000) >> 40;
    *dst++ = (value & 0xff000000000000) >> 48;
    *dst++ = (value & 0xff00000000000000) >> 56;
}

uint64_t af_attr_get_uint64(uint8_t *src)
{
    if (src == NULL) {
        return 0;
    }

    return src[0] | (src[1] << 8) | (src[2] << 16) | (src[3] << 24) | ((uint64_t)src[4] << 32) | ((uint64_t)src[5] << 40) | ((uint64_t)src[6] << 48) | ((uint64_t)src[7] << 56);
}

void af_attr_store_int64(uint8_t *dst, int64_t value)
{
    if (dst == NULL) {
        return;
    }

    uint64_t valueU = *(uint64_t *)&value;
    *dst++ = valueU & 0xff;
    *dst++ = (valueU & 0xff00) >> 8;
    *dst++ = (valueU & 0xff0000) >> 16;
    *dst++ = (valueU & 0xff000000) >> 24;
    *dst++ = (valueU & 0xff00000000) >> 32;
    *dst++ = (valueU & 0xff0000000000) >> 40;
    *dst++ = (valueU & 0xff000000000000) >> 48;
    *dst++ = (valueU & 0xff00000000000000) >> 56;
}

int64_t af_attr_get_int64(uint8_t *src)
{
    if (src == NULL) {
        return 0;
    }

    uint64_t valueU = src[0] | (src[1] << 8) | (src[2] << 16) | (src[3] << 24) | ((uint64_t)src[4] << 32) | ((uint64_t)src[5] << 40) | ((uint64_t)src[6] << 48) | ((uint64_t)src[7] << 56);
    return *(int64_t *)&valueU;
}

