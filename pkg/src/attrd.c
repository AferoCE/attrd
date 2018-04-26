/*
 * attrd.c -- attribute daemon
 *
 * Copyright (c) 2016-2018 Afero, Inc. All rights reserved.
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
#include <signal.h>
#include "af_attr_def.h"
#include "af_attr_client.h" // AF_ATTR_MAX_LISTEN_RANGES
#include "attr_prv.h"
#include "attrd_attr.h"
#include "attr_script.h"
#include "af_log.h"
#include "af_rpc.h"
#include "af_mempool.h"
#include "af_ipc_server.h"

#ifdef BUILD_TARGET_DEBUG
uint32_t g_debugLevel = 3;
#else
uint32_t g_debugLevel = 1;
#endif

static af_ipcs_server_t *sServer = NULL;

typedef struct attrd_client_struct {
    struct attrd_client_struct *next;
    uint8_t opened;
    uint8_t pad;
    uint16_t ownerId;
    uint16_t clientId;
} attrd_client_t;

typedef struct notify_client_struct {
    struct notify_client_struct *next;
    attrd_client_t *client;
} notify_client_t;

static attrd_client_t *sClients = NULL;
static af_mempool_t *sClientPool = NULL;

static af_mempool_t *sNotifyClientPool = NULL;

typedef struct attr_struct {
    uint32_t id;
    uint16_t ownerId;
    uint16_t flags;
    uint16_t getTimeout;
    uint16_t pad;
    attrd_client_t *owner;
    notify_client_t *notify;
    char name[AF_ATTR_NAME_SIZE];
} attr_t;

#define _AF_ATTR_ATTRDEF(_attr_id_num,_attr_id_name,_attr_type,_attr_get_timeout,_attr_owner,_attr_flags) \
    { \
      .id = AF_ATTR_##_attr_owner##_##_attr_id_name, \
      .ownerId = AF_ATTR_OWNER_##_attr_owner, \
      .flags = _attr_flags, \
      .getTimeout = _attr_get_timeout, \
      .name = #_attr_owner "_" #_attr_id_name \
    }
attr_t sAttr[] = {
    _AF_ATTR_ATTRIBUTES
};
#undef _AF_ATTR_ATTRDEF

#define ARRAY_SIZE(_a) (sizeof(_a)/sizeof(_a[0]))
#define NUM_ATTR ARRAY_SIZE(sAttr)

#define _AF_ATTR_OWNERDEF(_owner) "IPC." #_owner
char sAttrClientNames[][AF_ATTR_OWNER_NAME_SIZE] = {
    _AF_ATTR_OWNERS
};
#undef _AF_ATTR_OWNERDEF

/* EDGE ATTRIBUTES: */
/* edge attribues: range 1-1023 */
#define _MCU_ATTRDEF(attr_id_num,_attr_id_name,_attr_type,_attr_get_timeout,_attr_owner,_attr_flags) \
    { \
      .id = attr_id_num, \
      .ownerId = AF_ATTR_OWNER_##_attr_owner, \
      .flags = _attr_flags, \
      .getTimeout = _attr_get_timeout, \
      .name = #_attr_id_name "_" \
    }

attr_t sEdgeAttrs[AF_ATTR_EDGE_END+1] = { [0 ... AF_ATTR_EDGE_END] =
    _MCU_ATTRDEF(0,  EDGE_ATTR, 0, AF_ATTR_EDGE_GET_TIMEOUT, HUBBY, (AF_ATTR_FLAG_WRITABLE | AF_ATTR_FLAG_NOTIFY))
};

#undef _MCU_ATTRDEF


static struct event_base *sEventBase = NULL;
static trans_context_t *sReadTrans = NULL;
static op_context_t *sOutstandingGets = NULL;
static op_context_t *sOutstandingSets = NULL;
static struct event *sPipeEvent = NULL;

#ifndef BUILD_TARGET_RELEASE
static void dump_attrd_state(void)
{
    AFLOG_DEBUG3("dump_attrd_state:Attributes");
    int i;
    for (i = 0; i < NUM_ATTR; i++) {
        AFLOG_DEBUG3("  attrId=%d owner=%s name=%s", sAttr[i].id, sAttrClientNames[sAttr[i].ownerId], sAttr[i].name);
        if (sAttr[i].notify) {
            notify_client_t *n;
            for (n = sAttr[i].notify; n; n = n->next) {
                AFLOG_DEBUG3("    notify=%s", sAttrClientNames[n->client->ownerId]);
            }
        }
    }
    AFLOG_DEBUG3("dump_attrd_state:Clients");
    attrd_client_t *c;
    for (c = sClients; c; c = c->next) {
        AFLOG_DEBUG3("  name=%s", sAttrClientNames[c->ownerId]);
    }
}
#endif

static attrd_client_t *client_find_by_owner_id(uint16_t ownerId)
{
    attrd_client_t *c;
    for (c = sClients; c; c = c->next) {
        if (c->ownerId == ownerId) {
            return c;
        }
    }
    return NULL;
}

// return the ownerId given the client name
static uint16_t client_find_ownerId_by_name(char *name)
{
    int i, owner = AF_ATTR_OWNER_UNKNOWN;

    if (name == NULL) {
        AFLOG_ERR("client_find_owner_by_name: name = null");
        return AF_ATTR_OWNER_UNKNOWN;
    }

    for (i = 1; i < ARRAY_SIZE(sAttrClientNames); i++) {
        if (strcmp(name, sAttrClientNames[i]) == 0) {
            owner = i;
            break;
        }
    }
    return owner;
}

/* This function sets the pointer to the owner of each attribute owned by the client with
 * the specified name to the specified client struct. It also sets the ownerId in the
 * client struct to the ownerId that matches the name. It is called when the client
 * first opens a connection to the attribute daemon.
 */
static void notify_register_owner(attrd_client_t *client, char *name, uint8_t owner)
{
    int i;

    if (client == NULL || name == NULL) {
        AFLOG_ERR("notify_register_owner_param:client_null=%d,name_null=%d:", client == NULL, name == NULL);
        return;
    }

    client->ownerId = owner;

    if (owner == 0) {
        AFLOG_WARNING("handle_open_request_owner:name=%s:owner not found", name);
        return;
    }

    // edge attributes
    if (owner == AF_ATTR_OWNER_HUBBY) {
        for (i = AF_ATTR_EDGE_START; i <= AF_ATTR_EDGE_END; i++) {
            sEdgeAttrs[i].owner = client;
        }
    }

    for (i = 0; i < NUM_ATTR; i++) {
        if (sAttr[i].ownerId == owner) {
            sAttr[i].owner = client;
        }
    }
}

/* This function registers the specified client as an interested listener to the
 * attributes in the specified ranges. It is called when the client first opens a
 * connection to the attribute daemon.
 */
static void notify_register_client_with_ranges(attrd_client_t *client, af_attr_range_t *ranges, int numRanges)
{
    if (client == NULL || ranges == NULL || numRanges <=0) {
        AFLOG_ERR("notify_register_client_with_ranges_param:client_null=%d,ranges_null=%d,numRanges=%d",
                  client == NULL, ranges == NULL, numRanges);
        return;
    }

    int i;
    int j;
    for (i = 0; i < NUM_ATTR; i++) {
        uint32_t attrId = sAttr[i].id;
        for (j = 0; j < numRanges; j++) {
            if (attrId >= ranges[j].first && attrId <= ranges[j].last) {
                /* do not allow owner to register for its own notifications */
                if (sAttr[i].owner != client) {
                    notify_client_t *nc = (notify_client_t *)af_mempool_alloc(sNotifyClientPool);
                    if (nc != NULL) {
                        /* add to this attribute's notify list */
                        nc->client = client;
                        nc->next = sAttr[i].notify;
                        sAttr[i].notify = nc;
                    } else {
                        AFLOG_ERR("notify_register_client_table_alloc:attrId=%d", attrId);
                    }
                } else {
                    AFLOG_WARNING("owner_self_notify:owner=%s,attrId=%d:owner registration for notification on its own attribute ignored",
                                  sAttrClientNames[client->ownerId], attrId);
                }
            }
        }
    }

    //edge attributes
    for (j = 0; j < numRanges; j++) {
        if ((ranges[j].first >= AF_ATTR_EDGE_START) && (ranges[j].first <= AF_ATTR_EDGE_END)) {
            AFLOG_DEBUG1("notify_register_client_with_ranges:range[%d].first=%d, last=%d", j, ranges[j].first, ranges[j].last);

            if (sEdgeAttrs[ranges[j].first].owner != client) {
                int limit = (AF_ATTR_EDGE_END < ranges[j].last ? AF_ATTR_EDGE_END : ranges[j].last);
                for (i = ranges[j].first; i <= limit; i++) {
                    notify_client_t *nc = (notify_client_t *)af_mempool_alloc(sNotifyClientPool);
                    if (nc != NULL) {
                        nc->client = client;
                        nc->next = sEdgeAttrs[i].notify;
                        sEdgeAttrs[i].notify = nc;
                    } else {
                        AFLOG_ERR("notify_register_client_table_alloc:attrId=%d", i);
                    }
                }
            } else {
                AFLOG_WARNING("owner_self_notify:owner=%s,attrId=%d:owner registration for notification on its own attribute ignored",
                               sAttrClientNames[client->ownerId], i);
            }
        }
    }
}

static void remove_notify_client(notify_client_t **head, attrd_client_t *client)
{
    if (head != NULL && client != NULL) {
        notify_client_t *nc, *last = NULL;
        for (nc = *head; nc; nc = nc->next) {
            if (nc->client == client) {
                if (last) {
                    last->next = nc->next;
                } else {
                    *head = nc->next;
                }
                af_mempool_free(nc);
                break;
            }
            last = nc;
        }
    } else {
        AFLOG_ERR("remove_notify_client_param:head_NULL=%d,client_NULL=%d", head==NULL, client==NULL);
    }
}

/* This function is called when a client closes. It clears the owner of any attributes
 * the client owns and the notification client data for any attributes the client is
 * interested in.
 */
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
        remove_notify_client(&sAttr[i].notify, client);
    }

    // edge attributes
    for (i = AF_ATTR_EDGE_START; i <= AF_ATTR_EDGE_END; i++) {
        if (client->ownerId == AF_ATTR_OWNER_HUBBY) {
            sEdgeAttrs[i].owner = NULL;
        }
        remove_notify_client(&sEdgeAttrs[i].notify, client);
    }
}

/* This function returns a pointer to the attribute struct that matches the specified
 * attribute ID. If a linear search is too slow, this function can be changed to a binary
 * search.
 */
static attr_t *notify_find_attribute_with_id(uint32_t attrId)
{
    if ((attrId >= AF_ATTR_EDGE_START) && (attrId <= AF_ATTR_EDGE_END)) {
        return &sEdgeAttrs[attrId];
    }
    else {
        for (int i = 0; i < NUM_ATTR; i++) {
            if (sAttr[i].id == attrId) {
                return &sAttr[i];
            }
        }
    }
    return NULL;
}

/* This function is called when a notification transaction is complete. It decrements the
 * reference count for the notification's attr_value_t object. Note that this function
 * is also called if the notification transaction times out.
 */
static void cleanup_notification(int status, void *trans, void *context)
{
    trans_context_t *t = (trans_context_t *)trans;
    if (t != NULL) {
        attr_value_dec_ref_count(t->attrValue);
        trans_pool_free(t);
    } else {
        AFLOG_ERR("cleanup_notification_t::");
    }
}

/* This callback is used to send a request for the IPC server. The IPC server and IPC
 * client APIs are slightly different while the transaction transmit and receive functions
 * defined in attr_common.c are generic for client and server. Therefore we need this
 * callback is to provide a generic function to send a request to an attribute client.
 */
static int send_request(uint16_t clientId, uint8_t *buf, int bufSize, af_ipc_receive_callback_t receive, void *context, int timeoutMs)
{
    return af_ipcs_send_request(sServer, clientId, buf, bufSize, receive, context, timeoutMs);
}

/* This function notifies all interested clients of a new attribute value. It is called
 * from one of two places:
 *
 *    handle_set_request: The client that owns an attribute has set that attribute
 *    handle_set_reply:   A client that doesn't own an attribute has set that attribute,
 *                        the attribute daemon has asked the owner to set the attribute,
 *                        and the owner has replied that the set operation was success-
 *                        ful.
 *    send_attrd_set_response: A script has handled the set request
 */
static void notify_clients_of_attribute(attr_value_t *aValue, attr_t *a)
{
    int i;
    char hexBuf[80];
    if (g_debugLevel >= 1) {
        af_util_convert_data_to_hex_with_name("value", aValue->value, aValue->size, hexBuf, sizeof(hexBuf));
    }

    int numClients = 0;
    notify_client_t *nc;
    for (nc = a->notify; nc; nc = nc->next) {
        attrd_client_t *client = nc->client;
        numClients++;
        trans_context_t *t = trans_pool_alloc();
        if (t == NULL) {
            AFLOG_ERR("notify_clients_of_attribute_alloc:id=%d,numClients=%d:too many transactions", a->id, numClients);
            return; /* don't try to send any more */
        }

        /* add a reference to the attribute value */
        t->attrValue = aValue;
        attr_value_inc_ref_count(aValue);

        AFLOG_DEBUG1("notify_others:attrId=%d,client=%s,%s",
                     aValue->attrId, sAttrClientNames[client->ownerId], hexBuf);

        /* set the new opcode and data */
        t->opcode = AF_ATTR_OP_NOTIFY;
        t->pos = 0;

        int status = trans_transmit(client->clientId, t, send_request, cleanup_notification, t);
        if (status != AF_ATTR_STATUS_OK) {
            AFLOG_ERR("notify_clients_of_attribute_status:id=%d,numClients=%d,i=%d,clientName=%s,status=%d:failed to transmit",
                      a->id, numClients, i, sAttrClientNames[client->ownerId], status);
        }
    }
    /* allow the script handler to handle notify */
    script_notify(aValue);
}

/* This callback is used to send a response for the IPC server. The IPC server and IPC
 * client APIs are slightly different while the transaction transmit and receive functions
 * defined in attr_common.c are generic for client and server. Therefore we need this
 * callback is to provide a generic function to send a response to a request from an
 * attribute client.
 */
static int send_response(uint32_t seqNum, uint8_t *buf, int bufSize)
{
    return af_ipcs_send_response(sServer, seqNum, buf, bufSize);
}

/***************************************************************************************************************
 * Attribute Set
 */

/* This function is called when the client that owns an attribute replies to a set message
 * from the attribute daemon. The attribute daemon sent the message because another client
 * attempted to set the attribute. The purpose of this function is to reply to the set
 * message from the client originally setting the attribute and then notifying the
 * interested clients, if the set was successful. The owning client can reject the setting
 * of the attribute. In that case the interested clients are not notified of the change.
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

    /* grab the data from the set context */
    uint16_t clientOpId = o->u.ss.clientOpId;
    uint16_t clientId = o->u.ss.clientId;
    attr_value_t *aValue = o->u.ss.attrValue;

    /* inform the client of the set status, but don't abort if any errors occur */
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
    attr_t *a = notify_find_attribute_with_id(aValue->attrId);
    if (a != NULL) {
        if (IS_NOTIFY(a->flags)) {
            if (status == AF_ATTR_STATUS_OK) {
                AFLOG_DEBUG1("set_attribute_succeeded_notify:name=%s:set attribute succeeded; notifying clients", a->name);
                notify_clients_of_attribute(aValue, a);
            } else {
                AFLOG_INFO("set_attribute_failed_notify:name=%s,status=%d:set attribute failed; not notifying clients", a->name, status);
            }
        } else {
            if (status == AF_ATTR_STATUS_OK) {
                AFLOG_DEBUG1("set_attribute_succeeded:name=%s:set attribute succeeded", a->name);
            } else {
                AFLOG_INFO("set_attribute_failed:name=%s,status=%d", a->name, status);
            }
        }
    } else {
        AFLOG_ERR("set_reply_attr_not_found:attrId=%d:attribute not found; giving up", aValue->attrId);
    }

    /* done with the set context; clean it up */
    attr_value_dec_ref_count(aValue);
    op_cleanup(&sOutstandingSets, o);
}

/* This function is called when the attribute daemon receives a set transaction from a
 * client for an attribute the client does not own. The function sends a new transaction
 * to the owner of the attribute containing the new value for the attribute. Because the
 * opcode is AF_ATTR_OP_SET, the client will send a special set response packet in
 * addition to sending the status of the transaction itself.
 */
static void notify_owner_of_attribute(uint16_t opId, attr_value_t *aValue, attrd_client_t *owner)
{
    if (aValue == NULL || owner == NULL) {
        AFLOG_ERR("notify_owner_of_attribute_param:aValue_null=%d,owner_null=%d:",
                  aValue == NULL, owner == NULL);
        return;
    }

    if (g_debugLevel >= 1) {
        char hexBuf[80];
        af_util_convert_data_to_hex_with_name("value", aValue->value, aValue->size, hexBuf, sizeof(hexBuf));
        AFLOG_DEBUG1("notify_owner_set:attrId=%d,owner=%s,%s",
                     aValue->attrId, sAttrClientNames[owner->ownerId], hexBuf);
    }
    trans_context_t *t = trans_pool_alloc();

    /* reset the position */
    t->pos = 0;
    t->opcode = AF_ATTR_OP_SET;
    t->opId = opId;

    /* add increment the ref count for the value */
    t->attrValue = aValue;
    attr_value_inc_ref_count(aValue);

    int status = trans_transmit(owner->clientId, t, send_request, cleanup_notification, t);
    if (status != AF_ATTR_STATUS_OK) {
        AFLOG_ERR("notify_owner_of_attribute_transmit:status=%d:", status);
        return;
    }
}

/* This function is called in the following case: a client has set the value of an
 * attribute that it doesn't own. The attribute daemon has notified the owner of the new
 * value of the attribute, but the owner has not replied after AF_ATTR_SET_TIMEOUT seconds.
 */
static void handle_set_timeout(evutil_socket_t fd, short what, void *context)
{
    uint16_t setId = (uint16_t)(uint32_t)context;
    op_context_t *s = op_find(sOutstandingSets, setId);
    if (s != NULL) {
        uint8_t txBuf[32];

        AFLOG_ERR("handle_set_timeout:getId=%d", s->opId);
        int len = set_reply_create_rpc(AF_ATTR_STATUS_TIMEOUT, s->u.ss.clientOpId, txBuf, sizeof(txBuf));
        if (len >= 0) {
            if (af_ipcs_send_unsolicited(sServer, s->u.ss.clientId, txBuf, len) < 0) {
                AFLOG_ERR("handle_set_timeout_ipc:errno=%d:", errno);
            }
        } else {
            AFLOG_ERR("handle_set_timeout_rpc:len=%d:", len);
        }

        /* clean up transaction if owner doesn't respond because we won't send notification */
        attr_value_dec_ref_count(s->u.ss.attrValue);

        /* clean up the operation */
        op_cleanup(&sOutstandingSets, s);
    } else {
        AFLOG_WARNING("handle_set_timeout:setId=%d:set context not found; ignoring", setId);
    }
}

/* This function is called when a transaction is received by the attribute daemon and
 * the transaction opcode is AF_ATTR_OP_SET. There are several cases that are handled by
 * this function.
 *   1. Client owns the attribute. Notifies interested clients of the new attribute value
 *      if the notify bit is set in the attribute flags.
 *   2. Client does not own the attribute but the attribute daemon does. Calls
 *      handle_attrd_set_request and then notifies interested clients of the new attribute
 *      value if the notify bit is set in the attribute flags.
 *   3. Client and the attribute daemon do not own the attribute. Calls
 *      notify_owner_of_attribute.
 */
static void handle_set_request(trans_context_t *t, attrd_client_t *c)
{
    int status = AF_ATTR_STATUS_OK;

    /* check if this is a valid attribute */
    attr_t *a = notify_find_attribute_with_id(t->attrValue->attrId);
    if (a == NULL) {
        AFLOG_ERR("handle_set_request_no_attr:attrId=%d:", t->attrValue->attrId);
        status = AF_ATTR_STATUS_ATTR_ID_NOT_FOUND;
        goto exit;
    }

    if (a->owner == NULL && a->ownerId == AF_ATTR_OWNER_ATTRD) {
        /* this is an attribute owned by the attribute daemon itself */
        if (g_debugLevel >= 1) {
            char hexBuf[80];
            af_util_convert_data_to_hex_with_name("value", t->attrValue->value, t->attrValue->size, hexBuf, sizeof(hexBuf));
            AFLOG_DEBUG1("client_set_attrd_attribute:attrId=%d,name=%s,owner=%s,%s",
                         t->attrValue->attrId, a->name, sAttrClientNames[a->ownerId], hexBuf);
        }

        status = handle_attrd_set_request(a->id, t->attrValue->value, t->attrValue->size);

        if (status == AF_ATTR_STATUS_OK) {
            if (IS_NOTIFY(a->flags)) {
                notify_clients_of_attribute(t->attrValue, a);
            }
        }
    } else if (a->owner != NULL && a->owner == c) {
        /* the client setting the attribute owns the attribute; just notify others */
        if (g_debugLevel >= 1) {
            char hexBuf[80];
            af_util_convert_data_to_hex_with_name("value", t->attrValue->value, t->attrValue->size, hexBuf, sizeof(hexBuf));
            AFLOG_DEBUG1("client_set_own_attribute:attrId=%d,name=%s,owner=%s,%s",
                         t->attrValue->attrId, a->name, sAttrClientNames[a->ownerId], hexBuf);
        }
        if (IS_NOTIFY(a->flags)) {
            notify_clients_of_attribute(t->attrValue, a);
        }
    } else if (a->owner == NULL) {
        /* no owner is available so see if a script will handle the attribute */
        if (script_owner_set(c->clientId, t->opId, t->attrValue, (void *)a) == 0) {
            if (g_debugLevel >= 1) {
                char hexBuf[80];
                af_util_convert_data_to_hex_with_name("value", t->attrValue->value, t->attrValue->size, hexBuf, sizeof(hexBuf));
                AFLOG_DEBUG1("script_owner_set:attrId=%d,name=%s,owner=%s,%s",
                             t->attrValue->attrId, a->name, sAttrClientNames[a->ownerId], hexBuf);
            }
            /* send nothing now: waiting for script to provide status */
            trans_cleanup(t);
            return;
        } else {
            if (c != NULL && c->ownerId == AF_ATTR_OWNER_ATTRC) {
                /* attribute client can spoof an owner setting its own attribute */
                if (g_debugLevel >= 1) {
                    char hexBuf[80];
                    af_util_convert_data_to_hex_with_name("value", t->attrValue->value, t->attrValue->size, hexBuf, sizeof(hexBuf));
                    AFLOG_DEBUG1("attrc_spoof_owner_set:attrId=%d,name=%s,owner=%s,%s",
                                 t->attrValue->attrId, a->name, sAttrClientNames[a->ownerId], hexBuf);
                }
                if (IS_NOTIFY(a->flags)) {
                    notify_clients_of_attribute(t->attrValue, a);
                }
            } else {
                AFLOG_ERR("handle_set_request_no_owner:attrId=%d,ownerId=%d:", a->id, a->ownerId);
                status = AF_ATTR_STATUS_OWNER_NOT_AVAILABLE;
                goto exit;
            }
        }
    } else {
        /* the client attempting to set the attribute is not the owner */
        if (IS_WRITABLE(a->flags)) {
            if (g_debugLevel >= 1) {
                char hexBuf[80];
                af_util_convert_data_to_hex_with_name("value", t->attrValue->value, t->attrValue->size, hexBuf, sizeof(hexBuf));
                AFLOG_DEBUG1("client_set_another_clients_attribute:attrId=%d,name=%s,owner=%s,%s",
                             t->attrValue->attrId, a->name, sAttrClientNames[a->ownerId], hexBuf);
            }

            /* create a set context */
            op_context_t *s = op_alloc_with_timeout(sEventBase, AF_ATTR_SET_TIMEOUT, handle_set_timeout);

            if (s != NULL) {

                /* initialize the set context */
                s->u.ss.clientOpId = t->opId;
                s->u.ss.clientId = c->clientId;
                s->attrId = a->id;

                /* add the attribute value to the set context */
                s->u.ss.attrValue = t->attrValue;
                attr_value_inc_ref_count(t->attrValue);

                /* add to the outstanding set list */
                s->next = sOutstandingSets;
                sOutstandingSets = s;

                AFLOG_DEBUG3("handle_set_request_send:attrId=%u,getId=%d,timeout=%d", s->attrId, s->opId, s->timeout);

                /* notify the owner that its attribute has changed */
                notify_owner_of_attribute(s->opId, s->u.ss.attrValue, a->owner);

                /* send nothing now; waiting for owner to provide status */
                trans_cleanup(t);

                return;
            } else {
                /* no op contexts available */
                AFLOG_ERR("handle_set_request_alloc::");
                status = AF_ATTR_STATUS_NO_SPACE;
            }

        } else {
            AFLOG_ERR("handle_set_request_not_writable:attrId=%d:", a->id);
            status = AF_ATTR_STATUS_NOT_WRITABLE;
        }
    }

exit:
    {
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

        trans_cleanup(t);
    }
}

void send_attrd_set_response(uint8_t status, uint16_t clientId, uint16_t setId, attr_value_t *value, void *attr)
{
    if (value == NULL || attr == NULL) {
        AFLOG_ERR("send_attrd_set_response_param:value_NULL=%d,attr_NULL=%d", value==NULL, attr==NULL);
        return;
    }

    uint8_t txBuf[32];

    /* send back result */
    int len = set_reply_create_rpc(status, setId, txBuf, sizeof(txBuf));
    if (len >= 0) {
        if (af_ipcs_send_unsolicited(sServer, clientId, txBuf, len) < 0) {
            AFLOG_ERR("send_attrd_set_response_ipc:errno=%d:", errno);
        }
    } else {
        AFLOG_ERR("send_attrd_set_response_rpc:len=%d:", len);
    }

    /* notify clients of set */
    if (status == AF_ATTR_STATUS_OK) {
        notify_clients_of_attribute(value, (attr_t *)attr);
    }

    /* we're done with the value */
    attr_value_dec_ref_count(value);
}


/* This function is called when a transaction packet is received with the opcode set to
 * AF_ATTR_OP_SET. It receives the transaction packet. If it's the last packet, it calls
 * the handle_set_request function.
 */
static void handle_set_request_trans(uint8_t *rxBuf, int rxBufSize, attrd_client_t *client, uint32_t seqNum)
{
    trans_context_t *t = NULL;
    int status = trans_receive_packet(rxBuf, rxBufSize, &t, &sReadTrans, seqNum, sEventBase, send_response);

    if (status == AF_ATTR_STATUS_OK && t != NULL && t->u.rxc.timeoutEvent == NULL) {
        handle_set_request(t, client);
    }
}


/***************************************************************************************************************
 * Attribute Get
 */

/* This function is called when the client that owns an attribute requested by another
 * client replies with the value. This function forwards the response to the requesting
 * client.
 */
static void handle_get_reply(int reqStatus, uint32_t seqNum, uint8_t *rxBuf, int rxBufSize, void *context)
{
    uint16_t getId = (uint16_t)(uint32_t)context;

    op_context_t *g = op_find(sOutstandingGets, getId);
    if (g == NULL) {
        AFLOG_WARNING("handle_get_reply:getId=%d:get context not found; ignoring", getId);
        return;
    }

    uint8_t status = AF_ATTR_STATUS_OK;
    af_rpc_param_t params[3];
    uint8_t txBuf[AF_IPC_MAX_MSGLEN];
    int len;

    /* check request status */
    if (reqStatus != AF_IPC_STATUS_OK) {
        AFLOG_ERR("handle_get_reply_reqStatus:reqStatus=%d:", reqStatus);
        status = AF_ATTR_STATUS_UNSPECIFIED;
        goto exit;
    }

    if (rxBuf == NULL || rxBufSize <= 0) {
        AFLOG_ERR("handle_get_reply_param:rxBuf_null=%d,rxBufSize=%d", rxBuf == NULL, rxBufSize);
        status = AF_ATTR_STATUS_UNSPECIFIED;
        goto exit;
    }

    /* parse incoming message */
    len = af_rpc_get_params_from_buffer(params, ARRAY_SIZE(params), rxBuf, rxBufSize, AF_RPC_PERMISSIVE);
    if (len < 0) {
        AFLOG_ERR("handle_get_reply_rpc:len=%d:", len);
        status = AF_ATTR_STATUS_UNSPECIFIED;
        goto exit;
    }

    /* make sure we have at least two parameters */
    if (len < 2) {
        AFLOG_ERR("handle_get_reply_num_params:len=%d:", len);
        status = AF_ATTR_STATUS_UNSPECIFIED;
        goto exit;
    }

    if (params[0].type == AF_RPC_TYPE_UINT8) {
        status = AF_RPC_GET_UINT8_PARAM(params[0]);
    } else {
        AFLOG_ERR("handle_get_reply_param0_type:type=%d", params[0].type);
        status = AF_ATTR_STATUS_UNSPECIFIED;
        goto exit;
    }

    if (status != AF_ATTR_STATUS_OK) {
        AFLOG_ERR("handle_get_reply_status:status=%d:", status);
        goto exit;
    }

    uint16_t getIdReturned;

    if (params[1].type == AF_RPC_TYPE_UINT16) {
        getIdReturned = AF_RPC_GET_UINT16_PARAM(params[1]);
    } else {
        AFLOG_ERR("handle_get_reply_param1_type:type=%d", params[1].type);
        status = AF_ATTR_STATUS_UNSPECIFIED;
        goto exit;
    }

    AFLOG_DEBUG3("handle_get_reply_recv:status=%d,getId=%d,getIdReturned=%d", status, getId, getIdReturned);
    if (getIdReturned == 0) {
        if (len != 3) {
            AFLOG_ERR("handle_get_reply_fat_get_param:getId=%d,len=%d:fat get has incorrect number of parameters", getId, len);
            status = AF_ATTR_STATUS_UNSPECIFIED;
            goto exit;
        }
        if (!AF_RPC_TYPE_IS_BLOB(params[2].type)) {
            AFLOG_ERR("handle_get_reply_fat_get_param2_type:type=%d", params[2].type);
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

        AFLOG_DEBUG3("handle_get_reply_send_fat:status=%d,getId=%d,len=%d",
                     status, getId, AF_RPC_BLOB_SIZE(params[2].type));

        len = af_rpc_create_buffer_with_params(txBuf, sizeof(txBuf), params, 3);
        if (len < 0) {
            AFLOG_ERR("handle_get_reply_tx_fat_rpc:len=%d:", len);
            status = AF_ATTR_STATUS_UNSPECIFIED;
            goto exit;
        }
        if (af_ipcs_send_response(sServer, g->u.sg.clientSeqNum, txBuf, len) < 0) {
            AFLOG_ERR("handle_get_reply_tx_fat_ipc:errno=%d:", errno);
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

    AFLOG_DEBUG3("handle_get_reply_send:status=%d,getId=%d", status, g->u.sg.clientOpId);
    len = af_rpc_create_buffer_with_params(txBuf, sizeof(txBuf), params, 2);
    if (len < 0) {
        AFLOG_ERR("handle_get_reply_tx_rpc:len=%d:", len);
        return;
    }
    if (af_ipcs_send_response(sServer, g->u.sg.clientSeqNum, txBuf, len) < 0) {
        AFLOG_ERR("handle_get_reply_tx_ipc:errno=%d:", errno);
        return;
    }
    /* clean up if the get failed */
    /* otherwise get context is still needed to receive the transaction */
    if (status != AF_ATTR_STATUS_OK) {
        op_cleanup(&sOutstandingGets, g);
    }
}

/* This function is called when a client gets the value of an attribute and the entire get
 * transaction fails to the complete before get timeout for this attribute. This function
 * cleans up the get context associated with the request and sends the timeout status back
 * to the requesting client.
 */
static void handle_get_timeout(evutil_socket_t fd, short what, void *context)
{
    uint16_t getId = (uint16_t)(uint32_t)context;

    op_context_t *g = op_find(sOutstandingGets, getId);
    if (g != NULL) {
        uint8_t txBuf[AF_IPC_MAX_MSGLEN];
        af_rpc_param_t params[2];

        /* forward to requesting client */
        AF_RPC_SET_PARAM_AS_UINT8(params[0], AF_ATTR_STATUS_TIMEOUT);
        AF_RPC_SET_PARAM_AS_UINT16(params[1], g->u.sg.clientOpId);

        AFLOG_DEBUG3("handle_get_timeout_send:status=%d,getId=%d", AF_ATTR_STATUS_TIMEOUT, g->u.sg.clientOpId);
        int len = af_rpc_create_buffer_with_params(txBuf, sizeof(txBuf), params, ARRAY_SIZE(params));
        if (len >= 0) {
            if (af_ipcs_send_response(sServer, g->u.sg.clientSeqNum, txBuf, len) < 0) {
                AFLOG_ERR("on_get_request_timeout_tx_ipc:errno=%d:", errno);
            }
        } else {
            AFLOG_ERR("handle_get_timeout_tx_rpc:len=%d:", len);
        }

        op_cleanup(&sOutstandingGets, g);
    } else {
        AFLOG_WARNING("handle_get_timeout:getId=%d:timeout getting attribute; ignoring", getId);
    }
}

/* This function is called when a client requests an attribute that is owned by the
 * attribute daemon. At this time, only values small enough to fit within a fat get
 * structure can be returned by the attribute daemon.
 */
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

/* This function is called when a client gets the value of an attribute. The function
 * forwards the request to the client that owns the attribute.
 */
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
        /* owner is not available; try to see if there's a script to handle it */
        if (script_get(attrId, seqNum, getId) == 0) {
            /* don't do anything until the script finishes */
            return;
        } else {
            AFLOG_ERR("handle_get_request_owner:attrId=%d:owner not available", attrId);
            status = AF_ATTR_STATUS_OWNER_NOT_AVAILABLE;
            goto error;
        }
    }

    /* create a get context */
    g = op_alloc_with_timeout(sEventBase, attr->getTimeout, handle_get_timeout);
    if (g == NULL) {
        /* no get contexts available */
        AFLOG_ERR("handle_get_request_alloc::");
        status = AF_ATTR_STATUS_NO_SPACE;
        goto error;
    }

    /* initialize the get context */
    g->u.sg.clientSeqNum = seqNum;
    g->u.sg.clientOpId = getId;
    g->u.sg.clientId = af_ipc_get_client_id_from_seq_num(seqNum);
    g->attrId = attrId;

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
                             handle_get_reply, (void *)(uint32_t)g->opId,
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

/* This function is called when the transaction sending the attribute value requested by
 * a client to that client has completed. It cleans up both the transaction and the get
 * context.
 */
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

/* This function is called when the attribute daemon receives a transaction containing
 * attribute value data from a get request. This function receives the transaction and
 * sends the data to the requesting client once all of the transaction data has been
 * received.
 */
static void handle_get_reply_trans(uint8_t *rxBuf, int rxBufSize, attrd_client_t *client, uint32_t seqNum)
{
    trans_context_t *t = NULL;
    int status = trans_receive_packet(rxBuf, rxBufSize, &t, &sReadTrans, seqNum, sEventBase, send_response);

    AFLOG_DEBUG3("handle_get_reply_trans:status=%d,t_null=%d,timeout_null=%d",
                 status, t == NULL, t->u.rxc.timeoutEvent == NULL);

    if (status == AF_ATTR_STATUS_OK && t != NULL && t->u.rxc.timeoutEvent == NULL) {
        /* at this point t points to a valid transaction */
        op_context_t *g;
        for (g = sOutstandingGets; g; g = g->next) {
            if (g->opId == t->opId) {
                break;
            }
        }
        if (g == NULL) {
            AFLOG_ERR("handle_get_reply_trans:getId=%d:get not found", t->opId);
            goto exit;
        }

        if (g_debugLevel >= 1) {
            char hexBuf[80];
            af_util_convert_data_to_hex_with_name("value", t->attrValue->value, t->attrValue->size, hexBuf, sizeof(hexBuf));
            AFLOG_DEBUG1("owner_get_response:status=%d,attrId=%d,%s:owner sent get response; forwarding to requestor",
                         status, t->attrValue->attrId, hexBuf);
        }

        /* create a new transaction context to send the reply */
        trans_context_t *nt = trans_pool_alloc();
        if (nt == NULL) {
            AFLOG_ERR("handle_get_reply_alloc:");
            goto exit;
        }
        nt->opcode = AF_ATTR_OP_GET_REPLY;
        nt->pos = 0;
        nt->opId = g->u.sg.clientOpId;

        /* add the attribute value to the new transaction */
        nt->attrValue = t->attrValue;
        attr_value_inc_ref_count(t->attrValue);

        AFLOG_DEBUG3("handle_get_reply_trans:getId=%d,clientId=%d", nt->opId, g->u.sg.clientId);
        status = trans_transmit(g->u.sg.clientId, nt, send_request, on_get_reply_finished, g);
        if (status != 0) {
            AFLOG_ERR("handle_get_reply_trans_tx:status=%d:", status);
            goto exit;
        }
exit:
        trans_cleanup(t);
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
    uint16_t ownerId = AF_ATTR_OWNER_UNKNOWN;

    /* get the name */
    char name[AF_ATTR_OWNER_NAME_SIZE];
    int nameSize = sizeof(name) - 1;

    pos = af_rpc_get_blob_with_length_from_buffer_at_pos(name, &nameSize, rxBuf, rxBufSize, pos);
    if (pos < 0) {
        AFLOG_ERR("handle_open_request_get_params:pos=%d:", pos);
        goto exit;
    }
    name[nameSize] = '\0';

    ownerId = client_find_ownerId_by_name(name);
    AFLOG_INFO("handle_open_request: ownerId=%d (%s)", ownerId, name);
    if (ownerId != AF_ATTR_OWNER_UNKNOWN && ownerId != AF_ATTR_OWNER_ATTRC) {
        attrd_client_t *oldClient = client_find_by_owner_id(ownerId);
        if (oldClient) {
            AFLOG_WARNING("handle_open_request_dup_owner:name=%s:duplicate owner; dropping previous owner", name);
            af_ipcs_close_client(sServer, oldClient->clientId);
        }
    }
    if (ownerId != AF_ATTR_OWNER_UNKNOWN) {
        /* sets owner */
        notify_register_owner(client, name, ownerId);
    }

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
    client->clientId = af_ipc_get_client_id_from_seq_num(seqNum);

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
        /* allocate a client structure */
        attrd_client_t *c = af_mempool_alloc(sClientPool);
        if (c == NULL) {
            AFLOG_ERR("attrd_accept_calloc::failed to allocate client structure");
            return -1;
        }
        memset(c, 0, sizeof(attrd_client_t));

        /* initialize client structure */
        *clientContext = c;

        /* add to client list */
        c->next = sClients;
        sClients = c;
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

        if (af_ipc_seq_num_is_request(seqNum)) {
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
                    handle_get_reply_trans(rxBuffer, rxBufferSize, client, seqNum);
                    break;
                case AF_ATTR_OP_OPEN :
                    handle_open_request(rxBuffer, rxBufferSize, pos, client, seqNum);
                    break;
                default :
                    AFLOG_ERR("attrd_receive_request:opcode=%d:unknown request opcode", opcode);
                    break;
            }
        } else {
            /* this is unsolicited */
            switch(opcode) {
                case AF_ATTR_OP_SET_REPLY :
                    handle_set_reply(rxBuffer, rxBufferSize, pos);
                    break;
                default :
                    AFLOG_ERR("attrd_receive_unsol:opcode=%d:unknown unsolicited opcode", opcode);
                    break;
            }
        }
    } else {
        AFLOG_ERR("receive_callback:status=%d,rxBuffer=%p", status, rxBuffer);
    }
}

static void client_close_callback(int status, uint16_t clientId, void *clientContext)
{
    if (clientContext) {
        attrd_client_t *c = (attrd_client_t *)clientContext;
        /* clear client from attribute notify table */
        notify_unregister_client(c);

        /* remove from client list */
        attrd_client_t *rc, *last = NULL;

        for (rc = sClients; rc; rc = rc->next) {
            if (rc == c) {
                if (last) {
                    last->next = c->next;
                } else {
                    sClients = c->next;
                }
                /* free memory associated with the client */
                af_mempool_free(c);
                AFLOG_DEBUG3("attrd_close_client_found:client=%p",c);
                return;
            }
            last = rc;
        }
        AFLOG_ERR("attrd_close_client_not_found:client=%p",c);
    } else {
        AFLOG_ERR("attrd_close_client_context::client context is NULL");
    }
}

#define MAX_TRANSACTIONS (20)
#define MAX_OPS          (20)
#define NOTIFY_POOL_INC  (16)
#define MAX_CLIENTS      (16)

extern const char REVISION[];
extern const char BUILD_DATE[];

void on_pipe(evutil_socket_t fd, short what, void *context)
{
    AFLOG_NOTICE("SIGPIPE received");
}

int main(int argc, char *argv[])
{
    int retVal = 0;
    int transPoolStarted = 0;
    int opPoolStarted = 0;

    openlog("attrd", LOG_PID, LOG_USER);

    AFLOG_INFO("start_attrd:revision=%s,build_date=%s", REVISION, BUILD_DATE);

    /* enable pthreads */
    evthread_use_pthreads();

    /* get an event_base */
    sEventBase = event_base_new();
    if (sEventBase == NULL) {
        AFLOG_ERR("main_event_base_new::can't allocate event base");
        retVal = -1;
        goto exit;
    }

    sPipeEvent = evsignal_new(sEventBase, SIGPIPE, on_pipe, NULL);
    if (sPipeEvent == NULL) {
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

    if (op_pool_init(MAX_OPS) < 0) {
        AFLOG_ERR("attrd_op_pool_init::");
        errno = ENOMEM;
        retVal = -1;
        goto exit;
    }

    sClientPool = af_mempool_create(MAX_CLIENTS, sizeof(attrd_client_t), AF_MEMPOOL_FLAG_EXPAND);
    if (sClientPool == NULL) {
        AFLOG_ERR("attrd_client_pool_init::");
        errno = ENOMEM;
        retVal = -1;
        goto exit;
    }

    sNotifyClientPool = af_mempool_create(NOTIFY_POOL_INC, sizeof(notify_client_t), AF_MEMPOOL_FLAG_EXPAND);
    if (sNotifyClientPool == NULL) {
        AFLOG_ERR("attrd_notify_client_pool_init::");
        errno = ENOMEM;
        retVal = -1;
        goto exit;
    }

    /* edge attr db - set the id */
    for (int i=AF_ATTR_EDGE_START; i<=AF_ATTR_EDGE_END; i++) {
        char buf[10];
        sEdgeAttrs[i].id = i;
        sprintf(buf, "%d", i);
        strcat(sEdgeAttrs[i].name, buf);
        sEdgeAttrs[i].notify = NULL;
        sEdgeAttrs[i].owner = NULL;
    }

    /* clear out notify clients */
    int i;
    for (i = 0; i < NUM_ATTR; i++) {
        sAttr[i].notify = NULL;
        sAttr[i].owner = NULL;
    }

    sClients = NULL;

    sServer = af_ipcs_open(sEventBase, "IPC.ATTRD",
                           accept_callback, NULL,
                           receive_callback, client_close_callback);
    if (sServer == NULL) {
        AFLOG_ERR("main_server:errno=%d:", errno);
        retVal = -1;
        goto exit;
    }

    script_parse_config(sEventBase);

    script_init();

    event_base_dispatch(sEventBase);

/*
    int i;
    for (i = 0; i < ARRAY_SIZE(g_attributes); i++) {
        attr_t *at = &g_attributes[i];
        printf ("id=%d name=%s owner=%s flags=%d\n", at->id, at->name, g_attribute_client_names[at->owner], at->flags);
    }
*/

exit:
    if (sServer != NULL) {
        af_ipcs_close(sServer);
        sServer = NULL;
    }

    /* these functions are idempotent */
    trans_pool_deinit();
    op_pool_deinit();

    if (sPipeEvent != NULL) {
        event_free(sPipeEvent);
        sPipeEvent = NULL;
    }

    if (sEventBase != NULL) {
        event_base_free(sEventBase);
        sEventBase = NULL;
    }
//    libevent_global_shutdown();

    closelog();
    return retVal;
}
