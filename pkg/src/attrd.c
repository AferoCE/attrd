/*
 * attrd.c -- attribute daemon
 *
 * Copyright (c) 2016 Afero, Inc. All rights reserved.
 *
 * Clif Liu
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <string.h>
#include <errno.h>
#include "af_attr_def.h"
#include "af_attr_client.h" // AF_ATTR_MAX_LISTEN_RANGES
#include "attr_prv.h"
#include "attrd_attr.h"
#include "af_log.h"
#include "af_rpc.h"

#include "af_ipc_server.h"

uint32_t g_debugLevel = 3;
static af_ipcs_server_t *sServer = NULL;

#define MAX_NOTIFY_CLIENTS 4 // Maximum of clients that can be notified for a single attribute

typedef struct attrd_client_struct {
    uint8_t opened;
    uint8_t pad;
    uint16_t ownerId;
    uint16_t clientId;
} attrd_client_t;

static attrd_client_t *sClients[AF_IPCS_MAX_CLIENTS];

typedef struct attr_struct {
    uint32_t id;
    uint16_t ownerId;
    uint16_t flags;
    uint16_t getTimeout;
    uint16_t pad;
    attrd_client_t *owner;
    attrd_client_t *notify[MAX_NOTIFY_CLIENTS];
    char name[ATTR_NAME_SIZE];
} attr_t;

#define _ATTRDEF(_attr_id_num,_attr_id_name,_attr_type,_attr_get_timeout,_attr_owner,_attr_flags) \
    { \
      .id = AF_ATTR_##_attr_owner##_##_attr_id_name, \
      .ownerId = AF_ATTR_OWNER_##_attr_owner, \
      .flags = _attr_flags, \
      .getTimeout = _attr_get_timeout, \
      .name = #_attr_owner "_" #_attr_id_name \
    }
attr_t sAttr[] = {
    _ATTRIBUTES
};
#undef _ATTRDEF

#define ARRAY_SIZE(_a) (sizeof(_a)/sizeof(_a[0]))
#define NUM_ATTR ARRAY_SIZE(sAttr)

#define _OWNERDEF(_owner) "IPC." #_owner
char sAttrClientNames[][ATTR_OWNER_NAME_SIZE] = {
    _OWNERS
};
#undef _OWNERDEF



static struct event_base *sEventBase = NULL;
static trans_context_t *sReadTrans = NULL;
static op_context_t *sOutstandingGets = NULL;
static op_context_t *sOutstandingSets = NULL;

/* call with client set to NULL to find next free client */
static int client_find(attrd_client_t *client)
{
    int i;
    for (i = 0; i < AF_IPCS_MAX_CLIENTS; i++) {
        if (sClients[i] == client) {
            return i;
        }
    }
    return -1;
}

/* register attribute owner and set client's owner ID */
static void notify_register_owner(attrd_client_t *client, char *name)
{
    if (client == NULL || name == NULL) {
        AFLOG_ERR("notify_register_owner_param:client_null=%d,name_null=%d:", client == NULL, name == NULL);
        return;
    }

    int i, owner = 0;
    for (i = 1; i < ARRAY_SIZE(sAttrClientNames); i++) {
        if (strcmp(name, sAttrClientNames[i]) == 0) {
            owner = i;
        }
    }

    client->ownerId = owner;

    if (owner == 0) {
        AFLOG_WARNING("handle_open_request_owner:name=%s:owner not found", name);
        return;
    }

    for (i = 0; i < NUM_ATTR; i++) {
        if (sAttr[i].ownerId == owner) {
            sAttr[i].owner = client;
        }
    }
}

static void notify_register_client_with_ranges(attrd_client_t *client, af_attr_range_t *ranges, int numRanges)
{
    if (client == NULL || ranges == NULL || numRanges <=0) {
        AFLOG_ERR("notify_register_client_with_ranges_param:client_null=%d,ranges_null=%d,numRanges=%d",
                  client == NULL, ranges == NULL, numRanges);
        return;
    }

    int i;
    for (i = 0; i < NUM_ATTR; i++) {
        int j;
        uint32_t attrId = sAttr[i].id;
        for (j = 0; j < numRanges; j++) {
            if (attrId >= ranges[j].first && attrId <= ranges[j].last) {
                int k;
                /* do not allow owner to register for its own notifications */
                if (sAttr[i].owner != client) {
                    for (k = 0; k < MAX_NOTIFY_CLIENTS; k++) {
                        if (sAttr[i].notify[k] == NULL) {
                            sAttr[i].notify[k] = client;
                            break;
                        }
                    }
                    if (k >= MAX_NOTIFY_CLIENTS) {
                        AFLOG_ERR("notify_register_client_table_full:attrId=%d,k=%d", attrId, k);
                    }
                } else {
                    AFLOG_WARNING("owner_self_notify:owner=%s,attrId=%d:owner registration for notification on its own attribute ignored",
                                  sAttrClientNames[client->ownerId], attrId);
                }
            }
        }
    }
}

static void notify_unregister_client(attrd_client_t *client)
{
    if (client == NULL) {
        AFLOG_ERR("notify_unregister_client:client=NULL");
        return;
    }

    int i;
    for (i = 0; i < NUM_ATTR; i++) {
        if (sAttr[i].owner == client) {
            sAttr[i].owner = NULL;
        }
        int j;
        for (j = 0; j < MAX_NOTIFY_CLIENTS; j++) {
            if (sAttr[i].notify[j] == client) {
                sAttr[i].notify[j] = NULL;
            }
        }
    }
}

static attr_t *notify_find_attribute_with_id(uint32_t attrId)
{
    int i;
    for (i = 0; i < NUM_ATTR; i++) {
        if (sAttr[i].id == attrId) {
            return &sAttr[i];
        }
    }
    return NULL;
}

static void cleanup_notification(int status, void *trans, void *context)
{
    trans_context_t *t = (trans_context_t *)trans;
    if (t != NULL) {
        if (t->size > MAX_SIZE_FOR_INTERNAL_DATA) {
            /* decrement the refcount for the transaction memory */
            if (t->u.dataP) {
                trans_mem_dec_ref_count(t->u.dataP);
            } else {
                AFLOG_ERR("cleanup_notification_dataP:dataP=NULL,t->size=%d:", t->size);
            }
        }
        /* free the transaction */
        trans_pool_free(t);
    } else {
        AFLOG_ERR("cleanup_notification_t::");
    }
}

static int send_request(uint16_t clientId, uint8_t *buf, int bufSize, af_ipc_receive_callback_t receive, void *context, int timeoutMs)
{
    return af_ipcs_send_request(sServer, clientId, buf, bufSize, receive, context, timeoutMs);
}

static void notify_clients_of_attribute(trans_context_t *t, attr_t *a)
{
    /* count the number of clients to notify */
    int i, numClients = 0;
    trans_context_t *nt[MAX_NOTIFY_CLIENTS]; /* allocate on stack because IPC system will remember them */
    trans_mem_t refMem = NULL;

    memset(nt, 0, sizeof(nt));

    /* reset the position on the origin transaction */
    t->pos = 0;

    for (i = 0; i < MAX_NOTIFY_CLIENTS; i++) {
        if (a->notify[i]) {
            nt[i] = trans_pool_alloc();
            if (nt[i] == NULL) {
                AFLOG_ERR("notify_clients_of_attribute_alloc:id=%d,numClients=%d:too many transactions", a->id, numClients);
                goto error;
            }
            numClients++;
        } else {
            nt[i] = NULL;
        }
    }

    if (numClients != 0) {

        /* create reference count structure for transaction data */
        if (t->size > MAX_SIZE_FOR_INTERNAL_DATA) {
            refMem = trans_mem_create(t->u.dataP);
            if (refMem == NULL) {
                AFLOG_ERR("notify_clients_of_attribute_mem::can't allocate trans_mem");
                goto error;
            }
        }

        for (i = 0; i < MAX_NOTIFY_CLIENTS; i++) {
            attrd_client_t *client = a->notify[i];
            if (client != NULL) {
                if (nt[i] == NULL) {
                    AFLOG_ERR("notify_clients_of_attribute_ntnull:clientId=%d,i=%d", a->notify[i]->ownerId, i);
                    continue;
                }
                if (g_debugLevel >= 1) {
                    uint8_t *data = t->size > MAX_SIZE_FOR_INTERNAL_DATA ? t->u.dataP : t->u.data;
                    char hexBuf[80];
                    af_util_convert_data_to_hex_with_name("value", data, t->size, hexBuf, sizeof(hexBuf));
                    AFLOG_DEBUG1("notify_others:attrId=%d,client=%s,%s",
                                 t->attrId, sAttrClientNames[client->ownerId], hexBuf);
                }

                memcpy(nt[i], t, sizeof(trans_context_t));

                /* set the new opcode and data */
                nt[i]->opcode = AF_ATTR_OP_NOTIFY;
                if (refMem) {
                    nt[i]->u.dataP = refMem;
                }

                int status = trans_transmit(client->clientId, nt[i], send_request, cleanup_notification, NULL);
                if (status != AF_ATTR_STATUS_OK) {
                    AFLOG_ERR("notify_clients_of_attribute_status:id=%d,numClients=%d,i=%d,clientName=%s,status=%d:failed to transmit",
                              a->id, numClients, i, sAttrClientNames[client->ownerId], status);
                }
            }
        }
    }

    /* success! clean up transaction without cleaning up value memory */
    trans_pool_free(t);
    return;

error:
    /* free the allocated refcounted mem */
    if (refMem != NULL) {
        free(refMem);
    }

    /* free allocated notification transaction contexts */
    for (i = 0; i < numClients; i++) {
        if (nt[i] != NULL) {
            trans_pool_free(nt[i]);
        }
    }

    /* clean up the transaction */
    trans_cleanup(t);
}

static int send_response(uint32_t seqNum, uint8_t *buf, int bufSize)
{
    return af_ipcs_send_response(sServer, seqNum, buf, bufSize);
}

/***************************************************************************************************************/
/* SET
*/

static void handle_set_reply(uint8_t *rxBuf, int rxBufSize, int pos)
{
    uint8_t status;
    uint16_t setId;

    if (rxBuf == NULL || pos <= 0 || rxBufSize < 0) {
        AFLOG_ERR("handle_set_reply_param:rxBuf_null=%d,pos=%d,rxBufSize=%d", rxBuf==NULL, rxBufSize, pos);
        return;
    }

    /* read status */
    pos = af_rpc_get_uint8_from_buffer_at_pos(&status, rxBuf, rxBufSize, pos);
    if (pos < 0) {
        AFLOG_ERR("handle_set_reply_status:pos=%d", pos);
        /* we don't have enough information to send a packet back to client */
        return;
    }

    /* read setId */
    pos = af_rpc_get_uint16_from_buffer_at_pos(&setId, rxBuf, rxBufSize, pos);
    if (pos < 0) {
        AFLOG_ERR("handle_set_reply_setId:pos=%d", pos);
        /* we don't have enough information to send a packet back to client */
        return;
    }

    /* find the corresponding set context */
    op_context_t *o = op_find(sOutstandingSets, setId);

    if (o == NULL) {
        AFLOG_ERR("handle_set_reply_not_found:setId=%d:set ID of set reply not found; ignoring", setId);
        return;
    }

    /* grab the data and remove from outstanding set list */
    uint16_t clientOpId = o->u.ss.clientOpId;
    uint16_t clientId = o->u.ss.clientId;
    trans_context_t *t = (trans_context_t *)o->u.ss.trans;

    op_cleanup(&sOutstandingSets, o);

    /* forward this message to the client, but don't abort if any errors occur */
    uint8_t txBuf[32];
    int len = set_reply_create_rpc(status, clientOpId, txBuf, sizeof(txBuf));
    if (len < 0) {
        AFLOG_ERR("set_reply_create_rpc:len=%d", len);
    } else {
        if (af_ipcs_send_unsolicited(sServer, clientId, txBuf, len) < 0) {
            AFLOG_ERR("set_reply_send:errno=%d", errno);
        }
    }

    /* find the attribute and the interested clients */
    attr_t *a = notify_find_attribute_with_id(t->attrId);
    if (a == NULL) {
        AFLOG_ERR("set_reply_attr_not_found:attrId=%d:attribute not found; giving up", t->attrId);
        trans_cleanup(t);
        return;
    }

    if (IS_NOTIFY(a->flags)) {
        if (status == AF_ATTR_STATUS_OK) {
            AFLOG_DEBUG1("set_attribute_succeeded_notify:name=%s:set attribute succeeded; notifying clients", a->name);
            notify_clients_of_attribute(t, a);
        } else {
            AFLOG_INFO("set_attribute_failed_notify:name=%s,status=%d:set attribute failed; not notifying clients", a->name, status);
            trans_cleanup(t);
        }
    } else {
        if (status == AF_ATTR_STATUS_OK) {
            AFLOG_DEBUG1("set_attribute_succeeded:name=%s:set attribute succeeded", a->name);
        } else {
            AFLOG_INFO("set_attribute_failed:name=%s,status=%d", a->name, status);
        }
        trans_cleanup(t);
    }
}

static void notify_owner_of_attribute(trans_context_t *t, attrd_client_t *owner)
{
    if (t == NULL || owner == NULL) {
        AFLOG_ERR("notify_owner_of_attribute_param:t_null=%d,owner_null=%d:",
                  t == NULL, owner == NULL);
        return;
    }

    if (g_debugLevel >= 1) {
        uint8_t *data = t->size > MAX_SIZE_FOR_INTERNAL_DATA ? t->u.dataP : t->u.data;
        char hexBuf[80];
        af_util_convert_data_to_hex_with_name("value", data, t->size, hexBuf, sizeof(hexBuf));
        AFLOG_DEBUG1("notify_owner_set:attrId=%d,owner=%s,%s",
                     t->attrId, sAttrClientNames[owner->ownerId], hexBuf);
    }
    /* reset the position */
    t->pos = 0;

    int status = trans_transmit(owner->clientId, t, send_request, NULL, NULL);
    if (status != AF_ATTR_STATUS_OK) {
        AFLOG_ERR("notify_owner_of_attribute_transmit:status=%d:", status);
        return;
    }
}


static void on_attr_set_timeout(evutil_socket_t fd, short what, void *context)
{
    uint16_t setId = (uint16_t)(uint32_t)context;
    op_context_t *s = op_find(sOutstandingSets, setId);
    if (s != NULL) {
        uint8_t txBuf[32];

        AFLOG_ERR("on_attr_set_timeout:getId=%d", s->opId);
        int len = set_reply_create_rpc(AF_ATTR_STATUS_TIMEOUT, s->u.ss.clientOpId, txBuf, sizeof(txBuf));
        if (len >= 0) {
            if (af_ipcs_send_unsolicited(sServer, s->u.ss.clientId, txBuf, len) < 0) {
                AFLOG_ERR("on_attr_set_timeout_ipc:errno=%d:", errno);
            }
        } else {
            AFLOG_ERR("on_attr_set_timeout_rpc:len=%d:", len);
        }

        /* clean up transaction if owner doesn't respond because we won't send notification */
        trans_cleanup(s->u.ss.trans);

        /* clean up the operation */
        op_cleanup(&sOutstandingSets, s);
    } else {
        AFLOG_WARNING("on_attr_set_timeout:setId=%d:set context not found; ignoring", setId);
    }
}

static void handle_set_request(trans_context_t *t, attrd_client_t *c)
{
    int status = AF_ATTR_STATUS_OK;
    uint8_t *data = t->size > MAX_SIZE_FOR_INTERNAL_DATA ? t->u.dataP : t->u.data;

    /* check if this is a valid attribute */
    attr_t *a = notify_find_attribute_with_id(t->attrId);
    if (a == NULL) {
        AFLOG_ERR("handle_set_request_no_attr:attrId=%d:", t->attrId);
        status = AF_ATTR_STATUS_ATTR_ID_NOT_FOUND;
        goto exit;
    }

    /* check if the owner is available */
    if (a->owner == NULL) {
        if (a->ownerId == AF_ATTR_OWNER_ATTRD) {
            if (g_debugLevel >= 1) {
                char hexBuf[80];
                af_util_convert_data_to_hex_with_name("value", data, t->size, hexBuf, sizeof(hexBuf));
                AFLOG_DEBUG1("client_set_attrd_attribute:attrId=%d,name=%s,owner=%s,%s",
                             t->attrId, a->name, sAttrClientNames[a->ownerId], hexBuf);
            }

            /* handle the attribute daemon attribute set */
            status = handle_attrd_set_request(a->id, data, t->size);

            if (status == AF_ATTR_STATUS_OK) {
                if (IS_NOTIFY(a->flags)) {
                    notify_clients_of_attribute(t, a);
                }
            }
        } else {
            AFLOG_ERR("handle_set_request_no_owner:attrId=%d,ownerId=%d:", a->id, a->ownerId);
            status = AF_ATTR_STATUS_OWNER_NOT_AVAILABLE;
        }
    } else if (a->owner == c) {
        /* the client setting the attribute owns the attribute; just notify others */
        if (g_debugLevel >= 1) {
            char hexBuf[80];
            af_util_convert_data_to_hex_with_name("value", data, t->size, hexBuf, sizeof(hexBuf));
            AFLOG_DEBUG1("client_set_own_attribute:attrId=%d,name=%s,owner=%s,%s",
                         t->attrId, a->name, sAttrClientNames[a->ownerId], hexBuf);
        }
        if (IS_NOTIFY(a->flags)) {
            notify_clients_of_attribute(t, a);
        }
    } else {
        /* the client attempting to set the attribute is not the owner */
        if (IS_WRITABLE(a->flags)) {
            if (g_debugLevel >= 1) {
                char hexBuf[80];
                af_util_convert_data_to_hex_with_name("value", data, t->size, hexBuf, sizeof(hexBuf));
                AFLOG_DEBUG1("client_set_another_clients_attribute:attrId=%d,name=%s,owner=%s,%s",
                             t->attrId, a->name, sAttrClientNames[a->ownerId], hexBuf);
            }
            /* create a set context */
            op_context_t *s = op_pool_alloc();

            if (s != NULL) {

                /* initialize the set context */
                s->u.ss.clientOpId = t->opId;
                s->u.ss.clientId = c->clientId;
                s->u.ss.trans = t;
                s->attrId = a->id;
                s->timeout = SET_TIMEOUT;

                /* set a timeout event to clean up the context */
                s->timeoutEvent = allocate_and_add_timer(sEventBase, s->timeout * 1000, on_attr_set_timeout, (void *)(uint32_t)s->opId);
                if (s->timeoutEvent != NULL) {

                    /* add to the outstanding set list */
                    s->next = sOutstandingSets;
                    sOutstandingSets = s;

                    AFLOG_DEBUG3("handle_set_request_send:attrId=%u,getId=%d,timeout=%d", s->attrId, s->opId, s->timeout);

                    /* notify the owner that its attribute has changed */
                    t->opId = s->opId;
                    notify_owner_of_attribute(t, a->owner);

                    /* send nothing now; waiting for owner to provide status */
                    return;
                } else {
                    AFLOG_ERR("handle_attr_set_timer::can't allocate timer");

                    /* free up allocated set context */
                    op_pool_free(s);
                    status = AF_ATTR_STATUS_UNSPECIFIED;
                }

            } else {
                /* no get contexts available */
                AFLOG_ERR("handle_get_request_alloc::");
                status = AF_ATTR_STATUS_NO_SPACE;
            }

        } else {
            AFLOG_ERR("handle_set_request_not_writable:attrId=%d:", a->id);
            status = AF_ATTR_STATUS_NOT_WRITABLE;
        }
    }

exit:
    if (status != AF_ATTR_STATUS_OK) {
        /* we need to free the transaction */
        trans_cleanup(t);
    }

    /* send back a set reply */
    uint8_t txBuf[32];

    int len = set_reply_create_rpc(status, t->opId, txBuf, sizeof(txBuf));
    if (len >= 0) {
        if (af_ipcs_send_unsolicited(sServer, c->clientId, txBuf, len) < 0) {
            AFLOG_ERR("handle_set_request_send:errno=%d:", errno);
        }
    } else {
        AFLOG_ERR("handle_set_request_fwd_rpc:len=%d:", len);
    }

}

static void handle_set_request_trans(uint8_t *rxBuf, int rxBufSize, attrd_client_t *client, uint32_t seqNum)
{
    trans_context_t *t = NULL;
    int status = trans_receive_packet(rxBuf, rxBufSize, &t, &sReadTrans, seqNum, sEventBase, send_response);

    if (status == 0 && t != NULL && t->u2.rxc.timeoutEvent == NULL) {
        handle_set_request(t, client);
    }
}


/******************************************************************************************************************/
/* GET
*/

static void on_get_forward_response(int reqStatus, uint32_t seqNum, uint8_t *rxBuf, int rxBufSize, void *context)
{
    uint16_t getId = (uint16_t)(uint32_t)context;

    op_context_t *g = op_find(sOutstandingGets, getId);
    if (g == NULL) {
        AFLOG_WARNING("on_get_forward_response:getId=%d:get context not found; ignoring", getId);
        return;
    }

    uint8_t status = AF_ATTR_STATUS_OK;
    af_rpc_param_t params[3];
    uint8_t txBuf[AF_IPC_MAX_MSGLEN];
    int len;

    /* check request status */
    if (reqStatus != AF_IPC_STATUS_OK) {
        AFLOG_ERR("on_get_fwd_resp_reqStatus:reqStatus=%d:", reqStatus);
        status = AF_ATTR_STATUS_UNSPECIFIED;
        goto exit;
    }

    if (rxBuf == NULL || rxBufSize <= 0) {
        AFLOG_ERR("on_get_fwd_resp_param:rxBuf_null=%d,rxBufSize=%d", rxBuf == NULL, rxBufSize);
        status = AF_ATTR_STATUS_UNSPECIFIED;
        goto exit;
    }

    /* parse incoming message */
    len = af_rpc_get_params_from_buffer(params, ARRAY_SIZE(params), rxBuf, rxBufSize, AF_RPC_PERMISSIVE);
    if (len < 0) {
        AFLOG_ERR("on_get_fwd_resp_rpc:len=%d:", len);
        status = AF_ATTR_STATUS_UNSPECIFIED;
        goto exit;
    }

    /* make sure we have at least two parameters */
    if (len < 2) {
        AFLOG_ERR("on_get_fwd_resp_num_params:len=%d:", len);
        status = AF_ATTR_STATUS_UNSPECIFIED;
        goto exit;
    }

    if (params[0].type == AF_RPC_TYPE_UINT8) {
        status = AF_RPC_GET_UINT8_PARAM(params[0]);
    } else {
        AFLOG_ERR("on_get_fwd_resp_param0_type:type=%d", params[0].type);
        status = AF_ATTR_STATUS_UNSPECIFIED;
        goto exit;
    }

    if (status != AF_ATTR_STATUS_OK) {
        AFLOG_ERR("on_get_fwd_resp_status:status=%d:", status);
        goto exit;
    }

    uint16_t getIdReturned;

    if (params[1].type == AF_RPC_TYPE_UINT16) {
        getIdReturned = AF_RPC_GET_UINT16_PARAM(params[1]);
    } else {
        AFLOG_ERR("on_get_fwd_resp_param1_type:type=%d", params[1].type);
        status = AF_ATTR_STATUS_UNSPECIFIED;
        goto exit;
    }

    AFLOG_DEBUG3("on_get_forward_response_recv:status=%d,getId=%d,getIdReturned=%d", status, getId, getIdReturned);
    if (getIdReturned == 0) {
        if (len != 3) {
            AFLOG_ERR("on_get_fwd_resp_fat_get_param:getId=%d,len=%d:fat get has incorrect number of parameters", getId, len);
            status = AF_ATTR_STATUS_UNSPECIFIED;
            goto exit;
        }
        if (!AF_RPC_TYPE_IS_BLOB(params[2].type)) {
            AFLOG_ERR("on_get_fwd_resp_fat_get_param2_type:type=%d", params[2].type);
            status = AF_ATTR_STATUS_UNSPECIFIED;
            goto exit;
        }
        AF_RPC_SET_PARAM_AS_UINT8(params[0], AF_ATTR_STATUS_OK);
        AF_RPC_SET_PARAM_AS_UINT16(params[1], 0);
        /* params[2] is left exactly the same */

        if (g_debugLevel >= 1) {
            char hexBuf[80];
            af_util_convert_data_to_hex_with_name("value", params[2].base, AF_RPC_BLOB_SIZE(params[2].type), hexBuf, sizeof(hexBuf));
            AFLOG_DEBUG1("owner_fat_get_response:status=%d,attrId=%d,%s:owner sent fat get response; forwarding to requestor",
                         status, g->attrId, hexBuf);
        }

        AFLOG_DEBUG3("on_get_forward_response_send_fat:status=%d,getId=%d,len=%d",
                     status, getId, AF_RPC_BLOB_SIZE(params[2].type));

        len = af_rpc_create_buffer_with_params(txBuf, sizeof(txBuf), params, 3);
        if (len < 0) {
            AFLOG_ERR("on_get_fwd_resp_tx_fat_rpc:len=%d:", len);
            status = AF_ATTR_STATUS_UNSPECIFIED;
            goto exit;
        }
        if (af_ipcs_send_response(sServer, g->u.sg.clientSeqNum, txBuf, len) < 0) {
            AFLOG_ERR("on_get_fwd_resp_tx_fat_ipc:errno=%d:", errno);
            status = AF_ATTR_STATUS_UNSPECIFIED;
            goto exit;
        }
        /* we sent the value so we can clean up the outstanding get */
        op_cleanup(&sOutstandingGets, g);
        return;
    }

exit:
    /* forward to requesting client */
    AF_RPC_SET_PARAM_AS_UINT8(params[0], status);
    AF_RPC_SET_PARAM_AS_UINT16(params[1], g->u.sg.clientOpId);

    AFLOG_DEBUG3("on_get_forward_response_send:status=%d,getId=%d", status, g->u.sg.clientOpId);
    len = af_rpc_create_buffer_with_params(txBuf, sizeof(txBuf), params, 2);
    if (len < 0) {
        AFLOG_ERR("on_get_fwd_resp_tx_rpc:len=%d:", len);
        return;
    }
    if (af_ipcs_send_response(sServer, g->u.sg.clientSeqNum, txBuf, len) < 0) {
        AFLOG_ERR("on_get_fwd_resp_tx_ipc:errno=%d:", errno);
        return;
    }
    if (status != AF_ATTR_STATUS_OK) {
        op_cleanup(&sOutstandingGets, g);
    }
}

static void on_attr_get_timeout(evutil_socket_t fd, short what, void *context)
{
    uint16_t getId = (uint16_t)(uint32_t)context;

    op_context_t *g = op_find(sOutstandingGets, getId);
    if (g != NULL) {
        uint8_t txBuf[AF_IPC_MAX_MSGLEN];
        af_rpc_param_t params[2];

        /* forward to requesting client */
        AF_RPC_SET_PARAM_AS_UINT8(params[0], AF_ATTR_STATUS_TIMEOUT);
        AF_RPC_SET_PARAM_AS_UINT16(params[1], g->u.sg.clientOpId);

        AFLOG_DEBUG3("on_get_forward_response_send:status=%d,getId=%d", AF_ATTR_STATUS_TIMEOUT, g->u.sg.clientOpId);
        int len = af_rpc_create_buffer_with_params(txBuf, sizeof(txBuf), params, ARRAY_SIZE(params));
        if (len >= 0) {
            if (af_ipcs_send_response(sServer, g->u.sg.clientSeqNum, txBuf, len) < 0) {
                AFLOG_ERR("on_get_fwd_resp_tx_ipc:errno=%d:", errno);
            }
        } else {
            AFLOG_ERR("on_get_fwd_resp_tx_rpc:len=%d:", len);
        }

        op_cleanup(&sOutstandingGets, g);
    } else {
        AFLOG_WARNING("on_attr_get_timeout:getId=%d:timeout getting attribute; ignoring", getId);
    }
}

/* attrd attributes can only have fat get values */
void send_attrd_get_response(uint8_t status, uint32_t seqNum, uint16_t getId, uint8_t *value, int size)
{
    uint8_t txBuf[AF_IPC_MAX_MSGLEN];
    af_rpc_param_t params[3];
    int nParams = 2;

    if (value != NULL && size <= MAX_SEND_BLOB_SIZE && size >= 0) {
        AF_RPC_SET_PARAM_AS_BLOB(params[2], value, size);
        nParams = 3;
    } else {
        AFLOG_ERR("send_attr_get_resp_size:size=%d,maxSendSize=%d:send size too big for attrd attribute",
                  size, MAX_SEND_BLOB_SIZE);
        status = AF_ATTR_STATUS_UNSPECIFIED;
    }
    AF_RPC_SET_PARAM_AS_UINT8(params[0], status);
    AF_RPC_SET_PARAM_AS_UINT16(params[1], 0);
    int len = af_rpc_create_buffer_with_params(txBuf, sizeof(txBuf), params, nParams);
    if (len >= 0) {
        if (af_ipcs_send_response(sServer, seqNum, txBuf, len) < 0) {
            AFLOG_ERR("send_attrd_get_resp_send:errno=%d:", errno);
        }
    } else {
        AFLOG_ERR("send_attrd_get_resp_rpc:len=%d:", len);
    }
}


static void handle_get_request(uint8_t *rxBuf, int rxBufSize, int pos, attrd_client_t *client, uint32_t seqNum)
{
    AFLOG_DEBUG3("handle_get_request:pos=%d,rxBuf=%p:", pos, rxBuf);
    if (client == NULL || rxBuf == NULL || rxBufSize <= 0) {
        AFLOG_ERR("handle_get_reply_request_param:client_null=%d, rxBuf_null=%d,rxBufSize=%d",
                  client == NULL, rxBuf == NULL, rxBufSize);
        return;
    }

    uint8_t status = AF_ATTR_STATUS_OK;
    op_context_t *g = NULL;
    af_rpc_param_t params[2];
    uint8_t txBuf[AF_IPC_MAX_MSGLEN];
    int len;

    /* get the rest of the packet */
    uint32_t attrId;
    uint16_t getId;

    pos = af_rpc_get_uint32_from_buffer_at_pos(&attrId, rxBuf, rxBufSize, pos);
    if (pos < 0) {
        AFLOG_ERR("handle_get_request_attrId:pos=%d", pos);
        status = AF_ATTR_STATUS_BAD_TLV;
        goto error;
    }

    pos = af_rpc_get_uint16_from_buffer_at_pos(&getId, rxBuf, rxBufSize, pos);
    if (pos < 0) {
        AFLOG_ERR("handle_get_request_getId:pos=%d", pos);
        status = AF_ATTR_STATUS_BAD_TLV;
        goto error;
    }

    AFLOG_DEBUG3("handle_get_request_receive:attrId=%u,getId=%d", attrId, getId);

    /* find the attribute */
    attr_t *attr = notify_find_attribute_with_id(attrId);
    if (attr == NULL) {
        /* attribute ID not found */
        AFLOG_ERR("handle_get_request_attr:attrId=%d:attribute not found", attrId);
        status = AF_ATTR_STATUS_ATTR_ID_NOT_FOUND;
        goto error;
    }

    AFLOG_DEBUG1("client_get_request:attrId=%d,name=%s,owner=%s:client requested get; forwarding to owner",
                 attrId, attr->name, sAttrClientNames[attr->ownerId]);

    /* handle attrd owned get requests */
    if (attr->ownerId == AF_ATTR_OWNER_ATTRD) {
        handle_attrd_get_request(seqNum, getId, attr->id);
        return;
    }

    /* check if the owner is available */
    if (attr->owner == NULL) {
        /* owner is not available */
        AFLOG_ERR("handle_get_request_owner:attrId=%d:owner not available", attrId);
        status = AF_ATTR_STATUS_OWNER_NOT_AVAILABLE;
        goto error;
    }

    /* create a get context */
    g = op_pool_alloc();
    if (g == NULL) {
        /* no get contexts available */
        AFLOG_ERR("handle_get_request_alloc::");
        status = AF_ATTR_STATUS_NO_SPACE;
        goto error;
    }

    /* initialize the get context */
    g->u.sg.clientSeqNum = seqNum;
    g->u.sg.clientOpId = getId;
    g->u.sg.clientId = AF_IPC_GET_CLIENT_ID(seqNum);
    g->attrId = attrId;
    g->timeout = attr->getTimeout;

    /* set a timeout event to clean up the context */
    g->timeoutEvent = allocate_and_add_timer(sEventBase, g->timeout * 1000, on_attr_get_timeout, (void *)(uint32_t)g->opId);
    if (g->timeoutEvent == NULL) {
        AFLOG_ERR("on_attr_get_response_timer::");
        status = AF_ATTR_STATUS_UNSPECIFIED;
        goto error;
    }

    /* add to the outstanding get list */
    g->next = sOutstandingGets;
    sOutstandingGets = g;


    AFLOG_DEBUG3("handle_get_request_send:attrId=%u,getId=%d,timeout=%d", attrId, g->opId, g->timeout);

    /* forward request to owner */
    len = get_create_rpc(g, attrId, txBuf, sizeof(txBuf));
    if (len < 0) {
        AFLOG_ERR("handle_get_request_fwd_rpc:len=%d:", len);
        status = AF_ATTR_STATUS_UNSPECIFIED;
        goto error;
    }

    if (af_ipcs_send_request(sServer, attr->owner->clientId,
                             txBuf, len,
                             on_get_forward_response, (void *)(uint32_t)g->opId,
                             g->timeout * 1000) < 0) {
        AFLOG_ERR("handle_get_request_fwd_ipc:errno=%d:", errno);
        status = AF_ATTR_STATUS_UNSPECIFIED;
        goto error;
    }

    return;

error:
    if (g) {
        op_cleanup(&sOutstandingGets, g);
    }

    /* send response back to caller */
    AF_RPC_SET_PARAM_AS_UINT8(params[0], status);
    AF_RPC_SET_PARAM_AS_UINT16(params[1], getId);

    AFLOG_DEBUG3("handle_get_request_resp:status=%d,getId=%d", status, getId);

    len = af_rpc_create_buffer_with_params(txBuf, sizeof(txBuf), params, 2);
    if (len < 0) {
        AFLOG_ERR("handle_get_request_rsp_rpc:len=%d:", len);
        return;
    }

    if (af_ipcs_send_response(sServer, seqNum, txBuf, len) < 0) {
        AFLOG_ERR("handle_get_request_rsp_ipc:errno=%d:", errno);
        return;
    }
    return;
}

static void on_get_reply_finished(int status, void *trans, void *context)
{
    if (trans == NULL || context == NULL) {
        AFLOG_ERR("on_get_reply_finished:trans_null=%d,context_null=%d",
                  trans == NULL , context == NULL);
        return;
    }
    if (status != 0) {
        AFLOG_ERR("on_get_reply_finished_status:status=%d", status);
    }
    op_context_t *g = (op_context_t *)context;
    trans_context_t *t = (trans_context_t *)trans;
    AFLOG_DEBUG3("on_get_reply_finished:getId=%d,transId=%d", g->opId, t->transId);
    trans_cleanup(t);
    op_cleanup(&sOutstandingGets, g);
}

static void handle_get_reply_request_trans(uint8_t *rxBuf, int rxBufSize, int pos, attrd_client_t *client, uint32_t seqNum)
{
    trans_context_t *t = NULL;
    int status = trans_receive_packet(rxBuf, rxBufSize, &t, &sReadTrans, seqNum, sEventBase, send_response);

    AFLOG_DEBUG3("handle_get_reply_request:status=%d,t_null=%d,timeout_null=%d",
                 status, t == NULL, t->u2.rxc.timeoutEvent == NULL);

    if (status == 0 && t != NULL && t->u2.rxc.timeoutEvent == NULL) {
        /* at this point t points to a valid transaction */
        op_context_t *g;
        for (g = sOutstandingGets; g; g = g->next) {
            if (g->opId == t->opId) {
                break;
            }
        }
        if (g == NULL) {
            AFLOG_ERR("handle_get_reply_req:getId=%d:get not found", t->opId);
            return;
        }

        if (g_debugLevel >= 1) {
            uint8_t *data = t->size > MAX_SIZE_FOR_INTERNAL_DATA ? t->u.dataP : t->u.data;
            char hexBuf[80];
            af_util_convert_data_to_hex_with_name("value", data, t->size, hexBuf, sizeof(hexBuf));
            AFLOG_DEBUG1("owner_get_response:status=%d,attrId=%d,%s:owner sent get response; forwarding to requestor", status, g->attrId, hexBuf);
        }

        /* set up the getId */
        t->opId = g->u.sg.clientOpId;
        /* reset the position to 0 so it will send */
        t->pos = 0;

        AFLOG_DEBUG3("handle_get_reply_request_trans:getId=%d,clientId=%d", t->opId, g->u.sg.clientId);
        status = trans_transmit(g->u.sg.clientId, t, send_request, on_get_reply_finished, g);
        if (status != 0) {
            AFLOG_ERR("handle_get_reply_tx:status=%d:", status);
            return;
        }
    }
}

static void handle_open_request(uint8_t *rxBuf, int rxBufSize, int pos, attrd_client_t *client, uint32_t seqNum)
{
    if (client == NULL || rxBuf == NULL || rxBufSize < 0) {
        AFLOG_ERR("handle_open_request_param:client_null=%d, rxBuf_null=%d,rxBufSize=%d",
                  client == NULL, rxBuf == NULL, rxBufSize);
        return;
    }

    uint8_t txBuf[32]; // buffer for the status response
    int status = AF_ATTR_STATUS_UNSPECIFIED;

    /* get the name */
    char name[ATTR_OWNER_NAME_SIZE];
    int nameSize = sizeof(name) - 1;

    pos = af_rpc_get_blob_with_length_from_buffer_at_pos(name, &nameSize, rxBuf, rxBufSize, pos);
    if (pos < 0) {
        AFLOG_ERR("handle_open_request_get_params:pos=%d:", pos);
        goto exit;
    }
    name[nameSize] = '\0';

    /* match the name to the owner ID and register it; also sets ownerId */
    notify_register_owner(client, name);

    uint16_t numRanges;
    pos = af_rpc_get_uint16_from_buffer_at_pos(&numRanges, rxBuf, rxBufSize, pos);
    if (numRanges > AF_ATTR_MAX_LISTEN_RANGES) {
        AFLOG_ERR("handle_open_request_numRanges:numRanges=%d", numRanges);
        status = AF_ATTR_STATUS_TOO_MANY_RANGES;
        goto exit;
    }

    if (numRanges > 0) {
        af_attr_range_t ranges[AF_ATTR_MAX_LISTEN_RANGES];
        int rangeSize = sizeof(ranges);
        pos = af_rpc_get_blob_with_length_from_buffer_at_pos(ranges, &rangeSize, rxBuf, rxBufSize, pos);
        if (pos < 0) {
            AFLOG_ERR("handle_open_request_ranges:pos=%d", pos);
            status = AF_ATTR_STATUS_BAD_TLV;
            goto exit;
        }

        if (rangeSize != numRanges * sizeof(af_attr_range_t)) {
            AFLOG_ERR("handle_open_request_range_size:numRanges=%d,rangeSize=%d", numRanges, rangeSize);
            status = AF_ATTR_STATUS_BAD_TLV;
            goto exit;
        }

        notify_register_client_with_ranges(client, ranges, numRanges);
    }

    client->opened = 1;
    client->clientId = AF_IPC_GET_CLIENT_ID(seqNum);

    status = AF_ATTR_STATUS_OK;

exit:

    af_rpc_init_buffer(txBuf, sizeof(txBuf));
    pos = af_rpc_add_uint8_to_buffer(txBuf, sizeof(txBuf), status);
    if (pos < 0) {
        AFLOG_ERR("handle_open_request_rpc:pos=%d:", pos);
        return;
    }

    if (af_ipcs_send_response(sServer, seqNum, txBuf, pos) < 0) {
        AFLOG_ERR("handle_open_request_send_response:errno=%d:", errno);
        return;
    }
}

static int accept_callback(void *accept_context, uint16_t clientId, void **clientContext)
{
    if (clientContext) {

        /* find an available slot in the client table */
        int cIndex;
        cIndex = client_find(NULL);
        if (cIndex < 0) {
            AFLOG_ERR("attrd_accept_client_table::failed to accept client; table is full");
            return -1;
        }

        /* allocate a client structure */
        attrd_client_t *c = calloc(1, sizeof(attrd_client_t));
        if (c == NULL) {
            AFLOG_ERR("attrd_accept_calloc::failed to allocate client structure");
            return -1;
        }

        /* initialize client structure, add to client table, and return to the IPC layer */
        *clientContext = c;
        sClients[cIndex] = c;
    } else {
        AFLOG_ERR("attrd_accept_client_context::client context is NULL");
        return -1;
    }
    return 0;
}

static void receive_callback(int status, uint32_t seqNum, uint8_t *rxBuffer, int rxBufferSize, void *clientContext)
{
    AFLOG_DEBUG3("attrd_receive_callback:rxBufferSize=%d", rxBufferSize);
    if (status == 0 && rxBuffer != NULL && clientContext != NULL) {
        attrd_client_t *client = (attrd_client_t *)clientContext;
        uint8_t opcode;
        int pos = af_rpc_get_uint8_from_buffer_at_pos(&opcode, rxBuffer, rxBufferSize, 0);
        if (pos < 0) {
            AFLOG_ERR("receive_callback_get_u8:pos=%d:", pos);
            return;
        }

        if (AF_IPC_GET_SEQ_ID(seqNum) == 0) {
            /* this is unsolicited */
            switch(opcode) {
                case AF_ATTR_OP_SET_REPLY :
                    handle_set_reply(rxBuffer, rxBufferSize, pos);
                    break;
                default :
                    AFLOG_ERR("attrd_receive_unsol:opcode=%d:unknown unsolicited opcode", opcode);
                    break;
            }
        } else {
            /* this is a request */
            switch(opcode) {
                case AF_ATTR_OP_NOTIFY :
                    AFLOG_ERR("attrd_receive_notify::attribute daemon should never receive a notification");
                    break;
                case AF_ATTR_OP_SET :
                    handle_set_request_trans(rxBuffer, rxBufferSize, client, seqNum);
                    break;
                case AF_ATTR_OP_GET :
                    handle_get_request(rxBuffer, rxBufferSize, pos, client, seqNum);
                    break;
                case AF_ATTR_OP_GET_REPLY :
                    handle_get_reply_request_trans(rxBuffer, rxBufferSize, pos, client, seqNum);
                    break;
                case AF_ATTR_OP_OPEN :
                    handle_open_request(rxBuffer, rxBufferSize, pos, client, seqNum);
                    break;
                default :
                    AFLOG_ERR("attrd_receive_request:opcode=%d:unknown request opcode", opcode);
                    break;
            }
        }
    } else {
        AFLOG_ERR("receive_callback:status=%d,rxBuffer=%p", status, rxBuffer);
    }
}

static void close_callback(void *clientContext)
{
    if (clientContext) {
        /* find client in table */
        int cIndex = client_find(clientContext);
        if (cIndex < 0) {
            AFLOG_ERR("attrd_close_not_found::client context not found");
            return;
        }

        /* clear client from attribute notify table */
        notify_unregister_client(clientContext);

        /* remove the client from the client table */
        sClients[cIndex] = NULL;

        /* free memory associated with the client */
        free(clientContext);
    } else {
        AFLOG_ERR("attrd_close_client_context::client context is NULL");
    }
}

#define MAX_TRANSACTIONS (20)
#define MAX_OPS          (20)

int main(int argc, char *argv[])
{
    int retVal = 0;
    int transPoolStarted = 0;
    int opPoolStarted = 0;

    openlog("attrd", LOG_PID, LOG_USER);

    /* enable pthreads */
    evthread_use_pthreads();

    /* get an event_base */
    sEventBase = event_base_new();
    if (sEventBase == NULL) {
        AFLOG_ERR("main_event_base_new::can't allocate event base");
        retVal = -1;
        goto exit;
    }

    /* allocate pools */
    if (trans_pool_init(MAX_TRANSACTIONS) < 0) {
        AFLOG_ERR("attrd_trans_pool_init::");
        errno = ENOMEM;
        retVal = -1;
        goto exit;
    }
    transPoolStarted = 1;

    if (op_pool_init(MAX_OPS) < 0) {
        AFLOG_ERR("attrd_op_pool_init::");
        errno = ENOMEM;
        retVal = -1;
        goto exit;
    }
    opPoolStarted = 1;

    /* clear out notify clients */
    int i;
    for (i = 0; i < NUM_ATTR; i++) {
        memset(sAttr[i].notify, 0, sizeof(sAttr[i].notify));
    }

    /* clear out client list */
    memset(sClients, 0, sizeof(sClients));

    sServer = af_ipcs_init(sEventBase, "IPC.ATTRD",
                            accept_callback, NULL,
                            receive_callback, close_callback);
    if (sServer == NULL) {
        AFLOG_ERR("main_server:errno=%d:", errno);
        retVal = -1;
        goto exit;
    }

    event_base_dispatch(sEventBase);

/*
    int i;
    for (i = 0; i < ARRAY_SIZE(g_attributes); i++) {
        attr_t *at = &g_attributes[i];
        printf ("id=%d name=%s owner=%s flags=%d\n", at->id, at->name, g_attribute_client_names[at->owner], at->flags);
    }
*/

exit:
    if (transPoolStarted) {
        trans_pool_deinit();
    }

    if (opPoolStarted) {
        op_pool_deinit();
    }

    if (sServer != NULL) {
        af_ipcs_shutdown(sServer);
        sServer = NULL;
    }

    if (sEventBase != NULL) {
        event_base_free(sEventBase);
        sEventBase = NULL;
    }
//    libevent_global_shutdown();

    closelog();
    return retVal;
}
