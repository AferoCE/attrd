/*
 * attr_api.c -- attribute daemon client library
 *
 * Copyright (c) 2016 Afero, Inc. All rights reserved.
 *
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include "af_ipc_client.h"
#include "af_rpc.h"
#include "af_attr_client.h"
#include "attr_prv.h"
#include "af_attr_def.h"
#include "af_log.h"

typedef struct {
    struct event_base *base;
    af_ipcc_server_t *server;
    void *context;
    af_attr_notify_callback_t notifyCallback;
    af_attr_set_request_callback_t ownerSetCallback;
    af_attr_get_request_callback_t getReqCallback;
    af_attr_status_callback_t closeCallback;
    af_attr_status_callback_t openCallback;
    uint8_t serverOpened;
    uint8_t serverStarted;
} client_t;

typedef struct attr_timeout_struct {
    uint32_t attrId;
    uint16_t getTimeout;
    uint16_t pad;
} attr_timeout_t;

#define _ATTRDEF(_attr_id_num,_attr_id_name,_attr_type,_attr_get_timeout,_attr_owner,_attr_flags) \
 { .attrId = _attr_id_num, .getTimeout = _attr_get_timeout }

static attr_timeout_t sAttrTimeouts[] = {
    _ATTRIBUTES
};

#undef _ATTRDEF

static client_t *sClient = NULL;
static trans_context_t *sReadTrans = NULL;

static op_context_t *sRequestedGets = NULL;
static op_context_t *sGetsToSend = NULL;
static op_context_t *sOutstandingSets = NULL;

static uint16_t get_timeout_for_attribute_id(uint32_t attrId)
{
    int i;
    for (i = 0; i < ARRAY_SIZE(sAttrTimeouts); i++) {
        if (attrId == sAttrTimeouts[i].attrId) {
            return sAttrTimeouts[i].getTimeout;
        }
    }
    return 0;
}

static void close_client (int status)
{
    if (sClient != NULL) {
        if (sClient->serverStarted) {
            af_ipcc_shutdown(sClient->server);
            sClient->serverOpened = 0;
            sClient->serverStarted = 0;
        }

        af_attr_status_callback_t cb = sClient->closeCallback;
        void *context = sClient->context;

        free(sClient);
        sClient = NULL;

        if (status != AF_ATTR_STATUS_OK && cb != NULL) {
            (cb)(status, context);
        }
    }
}


#define OPEN_TIMEOUT 1000

static void open_response_callback(int status, uint32_t seqNum, uint8_t *rxBuf, int rxSize, void *context)
{
    if (status != 0) {
        AFLOG_ERR("open_response:status=%d:open failed", status);
        status = AF_ATTR_STATUS_UNSPECIFIED;
        goto exit;
    }

    if (rxBuf == NULL || rxSize <= 0) {
        AFLOG_ERR("open_response_param:rxBuf_null=%d,rxSize=%d:", rxBuf == NULL, rxSize);
        status = AF_ATTR_STATUS_UNSPECIFIED;
        goto exit;
    }

    uint8_t openStatus;

    int pos = af_rpc_get_uint8_from_buffer_at_pos(&openStatus, rxBuf, rxSize, 0);
    if (pos < 0) {
        AFLOG_ERR("open_response_rpc:pos=%d:can't unpack RPC message", pos);
        status = AF_ATTR_STATUS_UNSPECIFIED;
        goto exit;
    }

    AFLOG_DEBUG3("open_response_callback:openStatus=%d", openStatus);

    if (openStatus != 0) {
        AFLOG_ERR("open_response_status:openStatus=%d:bad open status--closing", openStatus);
        status = openStatus;
        goto exit;
    }

    sClient->serverOpened = 1;

exit:
    if (sClient->openCallback) {
        (sClient->openCallback) (status, sClient->context);
    }
    if (status) {
        /* open did not complete properly; close */
        close_client(status);
    }
}


static int send_response(uint32_t seqNum, uint8_t *buf, int bufSize)
{
    return af_ipcc_send_response(sClient->server, seqNum, buf, bufSize);
}

static void on_transaction(uint8_t *rxBuf, int rxSize, uint32_t seqNum, uint8_t opcode)
{
    trans_context_t *t = NULL;
    int status = trans_receive_packet(rxBuf, rxSize, &t, &sReadTrans, seqNum, sClient->base, send_response);

    AFLOG_DEBUG3("on_transaction:status=%d,t_null=%d,timeout=%d",
                 status, t == NULL, (t != NULL && t->u2.rxc.timeoutEvent != NULL) ) ;

    if (status == 0) {
        if (t && t->u2.rxc.timeoutEvent == NULL) {
            /* get actual data */
            uint8_t *data = t->size > MAX_SIZE_FOR_INTERNAL_DATA ? t->u.dataP : t->u.data;
            switch (opcode) {
                case  AF_ATTR_OP_SET :
                    if (g_debugLevel >= 1) {
                        char hexBuf[80];
                        af_util_convert_data_to_hex_with_name("value", data, t->size, hexBuf, sizeof(hexBuf));
                        AFLOG_DEBUG1("client_received_owner_set:attrId=%d:%s", t->attrId, hexBuf);
                    }
                    if (sClient->ownerSetCallback) {
                        uint8_t setStatus = (uint8_t)(sClient->ownerSetCallback)(t->attrId, data, t->size, sClient->context);
                        uint8_t txBuf[30];
                        int len = set_reply_create_rpc(setStatus, t->opId, txBuf, sizeof(txBuf));
                        if (len < 0) {
                            AFLOG_ERR("client_set_reply_create_rpc:len=%d:failed to create RPC for set reply", len);
                        } else {
                            AFLOG_DEBUG1("client_sending_owner_set_status:attrId=%d,status=%d", t->attrId, status);
                            if (af_ipcc_send_unsolicited(sClient->server, txBuf, len) < 0) {
                                AFLOG_ERR("client_set_reply_send:errno=%d", errno);
                            }
                        }
                    }
                    break;

                case AF_ATTR_OP_NOTIFY :
                    if (g_debugLevel >= 1) {
                        char hexBuf[80];
                        af_util_convert_data_to_hex_with_name("value", data, t->size, hexBuf, sizeof(hexBuf));
                        AFLOG_DEBUG1("client_received_notify:attrId=%d:%s", t->attrId, hexBuf);
                    }
                    if (sClient->notifyCallback) {
                        (sClient->notifyCallback)(t->attrId, data, t->size, sClient->context);
                    }
                    break;

                case AF_ATTR_OP_GET_REPLY :
                {
                    op_context_t *g;
                    for (g = sRequestedGets; g; g = g->next) {
                        if (g->opId == t->opId) {
                            break;
                        }
                    }
                    if (g) {
                        if (g_debugLevel >= 1) {
                            char hexBuf[80];
                            af_util_convert_data_to_hex_with_name("value", data, t->size, hexBuf, sizeof(hexBuf));
                            AFLOG_DEBUG1("client_received_get_resp:attrId=%d:%s", t->attrId, hexBuf);
                        }
                        if (g->u.c.callback) {
                            ((af_attr_get_response_callback_t)(g->u.c.callback))
                                (0, t->attrId, data, t->size, g->u.c.context);
                        }
                        op_cleanup(&sRequestedGets, g);
                    } else {
                        AFLOG_ERR("client_get_reply_getId:getId=%d:get ID not found", t->opId);
                    }
                }
                    break;

                default :
                    AFLOG_ERR("handle_notify_set_getr_request_opcode:opcode=%d:", opcode);
                    break;
            }
            trans_cleanup(t);
        }
    } else {
        AFLOG_ERR("handle_notify_set_request_bad_status:status=%d:", status);
    }
}

static void on_attr_get_send_timeout(evutil_socket_t fd, short what, void *context)
{
    if (context != NULL) {
        op_context_t *g = (op_context_t *)context;
        AFLOG_ERR("client_get_response_timeout:getId=%d,attrId=%d", g->opId, g->attrId);
        op_cleanup(&sGetsToSend, g);
    }
}

static void on_get_request(uint8_t *rxBuf, int rxSize, int pos, uint32_t seqNum)
{
    if (rxBuf == NULL || rxSize <= 0 || pos <= 0 || pos >= rxSize) {
        AFLOG_ERR("handle_get_request_param:rxBuf_null=%d,rxSize=%d,pos=%d",
                  rxBuf == NULL, rxSize, pos);
        return;
    }
    uint32_t attrId;
    uint16_t getId;
    uint16_t timeout;

    pos = af_rpc_get_uint32_from_buffer_at_pos(&attrId, rxBuf, rxSize, pos);
    if (pos < 0) {
        AFLOG_ERR("handle_get_request_attrId:pos=%d", pos);
        return;
    }

    pos = af_rpc_get_uint16_from_buffer_at_pos(&getId, rxBuf, rxSize, pos);
    if (pos < 0) {
        AFLOG_ERR("handle_get_request_getId:pos=%d", pos);
        return;
    }

    timeout = get_timeout_for_attribute_id(attrId);
    if (timeout == 0) {
        AFLOG_ERR("handle_get_request_not_found:attrId=%d", attrId);
        return;
    }

    /* allocate a get request */
    op_context_t *g = op_pool_alloc();
    if (g == NULL) {
        AFLOG_ERR("handle_get_req_get_alloc::can't allocate get context");
        goto error;
    }

    g->u.sg.clientSeqNum = seqNum;
    g->u.sg.clientOpId = getId;
    g->attrId = attrId;
    g->timeout = timeout;

    g->timeoutEvent = allocate_and_add_timer(sClient->base, g->timeout * 1000, on_attr_get_send_timeout, g);
    if (g->timeoutEvent == NULL) {
        AFLOG_ERR("handle_get_request_timer::");
        goto error;
    }

    AFLOG_DEBUG1("client_received_get_req:attrId=%d,getId=%d", attrId, g->opId);

    /* add get to list of gets waiting to be sent */
    g->next = sGetsToSend;
    sGetsToSend = g;

    if (sClient->getReqCallback) {
        (sClient->getReqCallback) (attrId, g->opId, sClient->context);
    }

    return;

error:
    if (g) {
        op_cleanup(&sGetsToSend, g);
    }
    {
        /* send an unspecified error packet back */
        uint8_t buf[30];
        af_rpc_param_t params[2];
        AF_RPC_SET_PARAM_AS_UINT8(params[0], AF_ATTR_STATUS_UNSPECIFIED);
        AF_RPC_SET_PARAM_AS_UINT16(params[1], getId);
        int len = af_rpc_create_buffer_with_params(buf, sizeof(buf), params, ARRAY_SIZE(params));
        if (len >= 0) {
            if (af_ipcc_send_response(sClient->server, seqNum, buf, len) < 0) {
                AFLOG_ERR("on_get_response_send:errno=%d", errno);
            }
        } else {
            AFLOG_ERR("on_get_response_rpc:len=%d", len);
        }
    }
}

static void on_set_reply(uint8_t *rxBuf, int rxSize)
{
    /* first let's unpack the rpc */
    af_rpc_param_t params[3];
    params[0].type = AF_RPC_TYPE_UINT8;
    params[1].type = AF_RPC_TYPE_UINT8;
    params[2].type = AF_RPC_TYPE_UINT16;
    int np = af_rpc_get_params_from_buffer(params, ARRAY_SIZE(params), rxBuf, rxSize, AF_RPC_STRICT);
    if (np < 0) {
        AFLOG_ERR("on_get_reply_rpc:np=%d:can't parse set reply", np);
        return;
    }
    uint8_t status = AF_RPC_GET_UINT8_PARAM(params[1]);
    uint16_t setId = AF_RPC_GET_UINT16_PARAM(params[2]);

    op_context_t *o;
    for (o = sOutstandingSets; o; o = o->next) {
        if (o->opId == setId) {
            break;
        }
    }
    if (o == NULL) {
        AFLOG_ERR("on_get_reply_rpc:setId=%d:set ID not found; ignoring", setId);
        return;
    }

    AFLOG_DEBUG1("client_set_reply:attrId=%d,status=%d", o->attrId, status);

    /* call callback if it exists */
    if (o->u.c.callback) {
        ((af_attr_set_response_callback_t)(o->u.c.callback))(status, o->attrId, o->u.c.context);
    }
    op_cleanup(&sOutstandingSets, o);
}

static void unsol_callback (int status, uint32_t seqNum, uint8_t *rxBuf, int rxSize, void *context)
{
    AFLOG_DEBUG3("unsol_callback");
    if (status == 0 && rxBuf != NULL) {
        uint8_t opcode;
        int pos = af_rpc_get_uint8_from_buffer_at_pos(&opcode, rxBuf, rxSize, 0);
        if (pos < 0) {
            AFLOG_ERR("unsol_callback_unsol:err=%d,status=%d,rxSize=%d:rpc_get opcode failed",
                      pos, status, rxSize);
            return;
        }

        if (AF_IPC_GET_SEQ_ID(seqNum) == 0) {
            /* this is unsolicited */
            switch(opcode) {
                case AF_ATTR_OP_SET_REPLY :
                    on_set_reply(rxBuf, rxSize);
                    break;
                default :
                    AFLOG_ERR("unsol_callback_unsol:opcode=%d:unknown unsolicited opcode", opcode);
                    break;
            }
        } else {
            /* this is a request */
            switch(opcode) {
                case AF_ATTR_OP_NOTIFY :
                case AF_ATTR_OP_SET :
                case AF_ATTR_OP_GET_REPLY :
                    on_transaction(rxBuf, rxSize, seqNum, opcode);
                    break;
                case AF_ATTR_OP_GET :
                    on_get_request(rxBuf, rxSize, pos, seqNum);
                    break;
                default :
                    AFLOG_ERR("unsol_callback_opcode:opcode=%d:unhandled request", opcode);
                    break;
            }
        }
    } else {
        AFLOG_ERR("receive_callback:status=%d,rxBuf=%p", status, rxBuf);
    }
}

static void close_callback (void *context)
{
    AFLOG_ERR("close_callback");
    close_client(AF_ATTR_STATUS_UNSPECIFIED);
}

#define MAX_TRANSACTIONS (10)
#define MAX_OPS          (10)

int af_attr_open (struct event_base *base,
                  char *clientName,
				  uint16_t numListenRanges, af_attr_range_t *listenRanges,
                  af_attr_notify_callback_t notifyCb,
				  af_attr_set_request_callback_t ownerSetCb,
				  af_attr_get_request_callback_t getReqCb,
				  af_attr_status_callback_t closeCb,
				  af_attr_status_callback_t openCb,
				  void *context)
{
    int status = AF_ATTR_STATUS_OK;
    uint8_t transPoolStarted = 0;
    uint8_t opPoolStarted = 0;

    if (base == NULL || clientName == NULL || numListenRanges > AF_ATTR_MAX_LISTEN_RANGES) {
        AFLOG_ERR("af_attr_open_param:base_null=%d,clientName_null=%d,numListenRanges=%d:",
                  base == NULL, clientName == NULL, numListenRanges);
        return AF_ATTR_STATUS_BAD_PARAM;
    }

    if (trans_pool_init(MAX_TRANSACTIONS) < 0) {
        AFLOG_ERR("af_attr_open_trans_pool_init::");
        status = AF_ATTR_STATUS_NO_SPACE;
        goto exit;
    }
    transPoolStarted = 1;

    if (op_pool_init(MAX_OPS) < 0) {
        AFLOG_ERR("af_attr_open_op_pool_init::");
        status = AF_ATTR_STATUS_NO_SPACE;
        goto exit;
    }
    opPoolStarted = 1;

    sClient = calloc(1, sizeof(client_t));
    if (sClient == NULL) {
        AFLOG_ERR("attr_api_open_alloc_client::client struct allocation failed");
        status = AF_ATTR_STATUS_NO_SPACE;
        goto exit;
    }

    sClient->notifyCallback = notifyCb;
    sClient->ownerSetCallback = ownerSetCb;
    sClient->getReqCallback = getReqCb;
    sClient->openCallback = openCb;
    sClient->closeCallback = closeCb;
    sClient->context = context;
    sClient->base = base;

    sClient->server = af_ipcc_get_server(base, "IPC.ATTRD",
                                         unsol_callback, NULL,
                                         close_callback);
    if (sClient->server == NULL) {
        AFLOG_ERR("attr_api_open:get_server:errno=%d:failed to get server", errno);
        status = AF_ATTR_STATUS_NO_DAEMON;
        goto exit;
    }

    sClient->serverStarted = 1;

    /* tell the server information about the client */
    uint8_t txBuffer[AF_IPC_MAX_MSGLEN];
    af_rpc_param_t params[4];
    int np = 3;

    AF_RPC_SET_PARAM_AS_UINT8(params[0], AF_ATTR_OP_OPEN);
    AF_RPC_SET_PARAM_AS_BLOB(params[1], clientName, strlen(clientName));
    AF_RPC_SET_PARAM_AS_UINT16(params[2], numListenRanges);
    if (numListenRanges > 0) {
        AF_RPC_SET_PARAM_AS_BLOB(params[3], listenRanges, numListenRanges * sizeof(af_attr_range_t));
        np = 4;
    }

    int pos = af_rpc_create_buffer_with_params(txBuffer, sizeof(txBuffer), params, np);
    if (pos < 0) {
        AFLOG_ERR("attr_api_open:af_rpc_create_buffer:pos=%d:", pos);
        status = AF_ATTR_STATUS_BAD_DATA;
        goto exit;
    }

    /* send the message */
    if (af_ipcc_send_request(sClient->server, txBuffer, pos, open_response_callback, NULL, OPEN_TIMEOUT) < 0) {
        AFLOG_ERR("attr_api_open:af_ipc_send_message:errno=%d:can't send listen length", errno);
        status = AF_ATTR_STATUS_UNSPECIFIED;
        goto exit;
    }

    return status;

exit:
    close_client(AF_ATTR_STATUS_OK);

    if (transPoolStarted) {
        trans_pool_deinit();
    }

    if (opPoolStarted) {
        op_pool_deinit();
    }

    return status;
}

static void on_transmit_finished(int status, void *trans, void *context)
{
    if (trans) {
        trans_context_t *t = (trans_context_t *)trans;
        trans_cleanup(t);
    }
}

static int send_request(uint16_t clientId, uint8_t *buf, int bufSize, af_ipc_receive_callback_t receive, void *context, int timeoutMs)
{
    return af_ipcc_send_request(sClient->server, buf, bufSize, receive, context, timeoutMs);
}


static void on_attr_set_timeout(evutil_socket_t fd, short what, void *context)
{
    if (context != NULL) {
        op_context_t *s = (op_context_t *)context;
        AFLOG_ERR("client_set_response_timeout:setId=%d,attrId=%d", s->opId, s->attrId);
        if (s->u.c.callback) {
            ((af_attr_set_response_callback_t)(s->u.c.callback))(AF_ATTR_STATUS_TIMEOUT, s->attrId, s->u.c.context);
        }
        op_cleanup(&sOutstandingSets, s);
    }
}

int af_attr_set (uint32_t attributeId, uint8_t *value, int length, af_attr_set_response_callback_t setCB, void *setContext)
{
    int status = AF_ATTR_STATUS_OK;
    op_context_t *s = NULL;

    if (sClient == NULL) {
        return AF_ATTR_STATUS_NOT_OPEN;
    }

    if (value == NULL || length <= 0 || length >= UINT16_MAX) {
        return AF_ATTR_STATUS_BAD_PARAM;
    }

    s = op_pool_alloc();
    if (s == NULL) {
        AFLOG_ERR("af_attr_set_alloc::can't allocate set context");
        status = AF_ATTR_STATUS_NO_SPACE;
        goto error;
    }

    s->u.c.callback = setCB;
    s->u.c.context = setContext;
    s->attrId = attributeId;
    s->timeout = SET_TIMEOUT;

    /* add to outstanding set list */
    s->next = sOutstandingSets;
    sOutstandingSets = s;

    s->timeoutEvent = allocate_and_add_timer(sClient->base, s->timeout * 1000, on_attr_set_timeout, s);
    if (s->timeoutEvent == NULL) {
        AFLOG_ERR("handle_set_request_timer::");
        goto error;
    }

    if (g_debugLevel >= 1) {
        char hexBuf[80];
        af_util_convert_data_to_hex_with_name("value", value, length, hexBuf, sizeof(hexBuf));
        AFLOG_DEBUG1("client_set:attrId=%d:%s", attributeId, hexBuf);
    }

    trans_context_t *t = NULL;
    status = AF_ATTR_STATUS_OK;

    t = trans_alloc(attributeId, AF_ATTR_OP_SET, value, length);
    if (t == NULL) {
        status = AF_ATTR_STATUS_NO_SPACE;
        goto error;
    }

    t->opId = s->opId;

    AFLOG_DEBUG3("af_attr_set:transmit_transId=%d", t->transId);
    status = trans_transmit(0, t, send_request, on_transmit_finished, NULL);

    if (status != 0) {
        /* trans_transmit calls the finish callback on failure */
        return status;
    }

    return AF_ATTR_STATUS_OK;

error:
    if (s) {
        op_cleanup(&sOutstandingSets, s);
    }

    if (t) {
        trans_cleanup(t);
    }
    return status;
}

static void on_attr_get_timeout(evutil_socket_t fd, short what, void *context)
{
    if (context != NULL) {
        op_context_t *g = (op_context_t *)context;
        AFLOG_ERR("on_attr_get_timeout:getId=%d", g->opId);
        if (g->u.c.callback) {
            ((af_attr_get_response_callback_t)(g->u.c.callback))
                (AF_ATTR_STATUS_TIMEOUT, g->attrId, NULL, 0, g->u.c.context);
        }
        op_cleanup(&sRequestedGets, g);
    }
}

static void on_attr_get_response(int status, uint32_t seqNum, uint8_t *rxBuf, int rxSize, void *context)
{
    /* context points to the op_context_t */
    if (context == NULL) {
        AFLOG_ERR("on_attr_get_response_context:");
        return;
    }

    op_context_t *g = (op_context_t *)context;
    uint8_t rStatus = AF_ATTR_STATUS_OK;
    int len;

    if (status != 0) {
        AFLOG_ERR("on_attr_get_response_resp_status:status=%d", status);
        rStatus = (status == AF_IPC_STATUS_TIMEOUT ? AF_ATTR_STATUS_TIMEOUT : AF_ATTR_STATUS_UNSPECIFIED);
        goto error;
    }

    /* note that here we are getting the response to the get request and not the attribute itself */
    if (rxBuf == NULL || rxSize <= 0) {
        AFLOG_ERR("on_attr_get_response_param:rxBuf_null=%d, size=%d",
                  rxBuf == NULL, rxSize);
        rStatus = AF_ATTR_STATUS_UNSPECIFIED;
        goto error;
    }

    af_rpc_param_t params[3];

    /* parse incoming message */
    len = af_rpc_get_params_from_buffer(params, ARRAY_SIZE(params), rxBuf, rxSize, AF_RPC_PERMISSIVE);
    if (len < 0) {
        AFLOG_ERR("on_attr_get_resp_rpc:len=%d:", len);
        rStatus = AF_ATTR_STATUS_UNSPECIFIED;
        goto error;
    }

    /* make sure we have at least two parameters */
    if (len < 2) {
        AFLOG_ERR("on_attr_get_resp_num_params:len=%d:", len);
        rStatus = AF_ATTR_STATUS_UNSPECIFIED;
        goto error;
    }

    if (params[0].type == AF_RPC_TYPE_UINT8) {
        rStatus = AF_RPC_GET_UINT8_PARAM(params[0]);
    } else {
        AFLOG_ERR("on_attr_get_resp_param0_type:type=%d", params[0].type);
        rStatus = AF_ATTR_STATUS_UNSPECIFIED;
        goto error;
    }

    if (rStatus != AF_ATTR_STATUS_OK) {
        AFLOG_ERR("on_attr_get_resp_status:rStatus=%d:", rStatus);
        goto error;
    }

    uint16_t getId;

    if (params[1].type == AF_RPC_TYPE_UINT16) {
        getId = AF_RPC_GET_UINT16_PARAM(params[1]);
    } else {
        AFLOG_ERR("on_attr_get_resp_param1_type:type=%d", params[1].type);
        rStatus = AF_ATTR_STATUS_UNSPECIFIED;
        goto error;
    }

    AFLOG_DEBUG3("on_attr_get_response:status=%d,getId=%d", status, getId);

    /* check if we have a fat get */
    if (getId == 0) {
        if (len != 3) {
            AFLOG_ERR("on_attr_get_resp_fat_get_param:getId=%d,len=%d:fat get has incorrect number of parameters", getId, len);
            status = AF_ATTR_STATUS_UNSPECIFIED;
            goto error;
        }
        if (!AF_RPC_TYPE_IS_BLOB(params[2].type)) {
            AFLOG_ERR("on_attr_get_resp_fat_get_param2_type:type=%d", params[2].type);
            status = AF_ATTR_STATUS_UNSPECIFIED;
            goto error;
        }
        /* return the info back to the user */

        if (g_debugLevel >= 1) {
            char hexBuf[80];
            af_util_convert_data_to_hex_with_name("value", params[2].base, AF_RPC_BLOB_SIZE(params[2].type), hexBuf, sizeof(hexBuf));
            AFLOG_DEBUG1("client_received_get_resp:attrId=%d:%s", g->attrId, hexBuf);
        }

        if (g->u.c.callback) {
            ((af_attr_get_response_callback_t)(g->u.c.callback))
                (rStatus, g->attrId, params[2].base, AF_RPC_BLOB_SIZE(params[2].type), g->u.c.context);
        }
        op_cleanup(&sRequestedGets,g);
    } else {
        /* we got a good response; now set timeout and wait for transaction containing actual attribute */
        g->timeoutEvent = allocate_and_add_timer(sClient->base, g->timeout * 1000, on_attr_get_timeout, g);
        if (g->timeoutEvent == NULL) {
            AFLOG_ERR("on_attr_get_response_timer::");
            rStatus = AF_ATTR_STATUS_NO_SPACE;
            goto error;
        }
    }

    return;

error:
    /* we don't expect a return transaction so let's notify the user */
    if (g->u.c.callback) {
        ((af_attr_get_response_callback_t)(g->u.c.callback))
            (rStatus, g->attrId, NULL, 0, g->u.c.context);
    }
    op_cleanup(&sRequestedGets,g);
}

int af_attr_get (uint32_t attributeId, af_attr_get_response_callback_t cb, void *context)
{
    int status = AF_ATTR_STATUS_OK;
    op_context_t *g = NULL;

    if (sClient == NULL) {
        return AF_ATTR_STATUS_NOT_OPEN;
    }

    uint16_t timeout = get_timeout_for_attribute_id(attributeId);
    if (timeout == 0) {
        status = AF_ATTR_STATUS_ATTR_ID_NOT_FOUND;
        goto error;
    }

    g = op_pool_alloc();
    if (g == NULL) {
        AFLOG_ERR("af_attr_get_alloc::can't allocate get context");
        status = AF_ATTR_STATUS_NO_SPACE;
        goto error;
    }

    g->u.c.callback = cb;
    g->u.c.context = context;
    g->attrId = attributeId;
    g->timeout = timeout;

    /* add to outstanding get list */
    g->next = sRequestedGets;
    sRequestedGets = g;

    uint8_t buf[AF_IPC_MAX_MSGLEN];

    int len = get_create_rpc(g, attributeId, buf, sizeof(buf));

    AFLOG_DEBUG1("client_get:attrId=%d", g->attrId);
    AFLOG_DEBUG3("af_attr_get:opId=%u", g->opId);

    if (len < 0) {
        AFLOG_ERR("af_attr_get_rpc::can't create_rpc");
        status = AF_ATTR_STATUS_UNSPECIFIED;
        goto error;
    }

    if (af_ipcc_send_request(sClient->server, buf, len, on_attr_get_response, g, timeout * 1000) < 0) {
        AFLOG_ERR("af_attr_get_send:errno=%d:can't send get request", errno);
        status = AF_ATTR_STATUS_UNSPECIFIED;
        goto error;
    }

    return AF_ATTR_STATUS_OK;

error:
    op_cleanup(&sRequestedGets, g);
    return status;
}

static void on_get_attribute_finished(int status, void *trans, void *context)
{
    if (trans != NULL) {
        trans_context_t *t = (trans_context_t *)trans;
        AFLOG_DEBUG3("on_get_attribute_finished:getId=%d", t->opId);
        trans_cleanup(t);
    }
}

int af_attr_send_get_response (int status, uint16_t getId, uint8_t *value, int length)
{
    if (sClient == NULL) {
        return AF_ATTR_STATUS_NOT_OPEN;
    }

    /* check parameters */
    if (getId == 0 || (status == AF_ATTR_STATUS_OK && value == NULL) ||
        length <= 0 || length >= UINT16_MAX || status < 0 || status >= AF_ATTR_STATUS_MAX) {
        AFLOG_ERR("af_attr_send_get_resp_param:status=%d,getId=%d,value_null=%d,length=%d",
                  status, getId, value == NULL, length);
        return AF_ATTR_STATUS_BAD_PARAM;
    }

    /* find get ID */
    op_context_t *g = NULL;
    for (g = sGetsToSend; g; g = g->next) {
        if (g->opId == getId) {
            break;
        }
    }
    if (g == NULL) {
        AFLOG_ERR("af_attr_send_get_resp_not_found:getId=%d:", getId);
        return AF_ATTR_STATUS_TRANSACTION_NOT_FOUND;
    }

    if (g_debugLevel >= 1) {
        char hexBuf[80];
        af_util_convert_data_to_hex_with_name("value", value, length, hexBuf, sizeof(hexBuf));
        AFLOG_DEBUG1("client_sending_get_resp:status=%d,attrId=%d,getId=%d:%s", status, g->attrId, getId, hexBuf);
    }

    /* create and send response */
    uint8_t txBuf[AF_IPC_MAX_MSGLEN];
    af_rpc_param_t params[3];
    int numParams = 2;
    trans_context_t *t = NULL;

    AF_RPC_SET_PARAM_AS_UINT8(params[0], status);

    if (status != AF_ATTR_STATUS_OK) {
        AF_RPC_SET_PARAM_AS_UINT16(params[1], g->opId);
    } else {
        if (length <= MAX_SEND_BLOB_SIZE) {
            AF_RPC_SET_PARAM_AS_UINT16(params[1], 0);            // getId of zero indicates that the value is sent directly
            AF_RPC_SET_PARAM_AS_BLOB(params[2], value, length);
            numParams = 3;
        } else {

            t = trans_alloc(g->attrId, AF_ATTR_OP_GET_REPLY, value, length);
            if (t == NULL) {
                AFLOG_ERR("af_attr_send_get_resp_talloc::");
                status = AF_ATTR_STATUS_NO_SPACE;
                goto error;
            }

            t->opId = g->u.sg.clientOpId;
            AF_RPC_SET_PARAM_AS_UINT16(params[1], t->opId);
        }
    }

    status = af_rpc_create_buffer_with_params(txBuf, sizeof(txBuf), params, numParams);
    if (status < 0) {
        AFLOG_ERR("af_attr_send_get_response_rpc:status=%d:", status);
        status = AF_ATTR_STATUS_UNSPECIFIED;
        goto error;
    }

    if (af_ipcc_send_response(sClient->server, g->u.sg.clientSeqNum, txBuf, status) < 0) {
        AFLOG_ERR("af_attr_send_get_response_send_resp:errno=%d:", errno);
        status = AF_ATTR_STATUS_UNSPECIFIED;
        goto error;
    }

    /* start transaction to send the data back */
    if (t != NULL) {
        status = trans_transmit(0, t, send_request, on_get_attribute_finished, NULL);

        if (status != AF_ATTR_STATUS_OK) {
            goto error;
        }
    }

    op_cleanup(&sGetsToSend, g);
    return status;

error:
    if (g != NULL) {
        op_cleanup(&sGetsToSend, g);
    }

    if (t != NULL) {
        trans_cleanup(t);
    }
    return status;
}

void af_attr_close (void)
{
    close_client(AF_ATTR_STATUS_OK);
    trans_pool_deinit();
    op_pool_deinit();
}
