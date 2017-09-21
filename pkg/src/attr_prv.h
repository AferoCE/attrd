/*
 * file attr_prv.h -- definitions common between attribute API and attribute daemon
 *
 * Copyright (c) 2016-2017 Afero, Inc. All rights reserved.
 *
 */
#ifndef __AF_ATTR_PRV_H__
#define __AF_ATTR_PRV_H__

#include "af_ipc_common.h"
#include "af_attr_client.h"

/* opcodes */
#define AF_ATTR_OP_OPEN         (0)
#define AF_ATTR_OP_NOTIFY       (1)
#define AF_ATTR_OP_SET          (2)
#define AF_ATTR_OP_GET          (3)
#define AF_ATTR_OP_SET_REPLY    (4)
#define AF_ATTR_OP_GET_REPLY    (5)

#define IS_WRITABLE(_x) ((_x & AF_ATTR_FLAG_WRITABLE) != 0)
#define IS_NOTIFY(_x) ((_x & AF_ATTR_FLAG_NOTIFY) != 0)

/* Messages that are sent:
 *
 * OPEN
 * client opens server
 * client sends to server:
 *   uint8_t  opcode (AF_ATTR_OP_OPEN)
 *   blob     clientName
 *   uint16_t numListenRanges
 *   blob     listenRanges (only if numListenRanges > 0)
 * server replys with
 *   uint8_t  status (see AF_ATTR_ISTATUS codes above)
 *
 * TRANSMIT ATTRIBUTE
 * sender sends to receiver
 *   uint8_t opcode (AF_ATTR_OP_SET, AF_ATTR_OP_NOTIFY, or AF_ATTR_OP_GET_REPLY)
 *   uint16_t transId (0 if first packet sent else transaction ID returned from receiver)
 *   uint16_t opId (this is the set id in the case of an attribute set)
 *   uint32_t attrId
 *   uint16_t size
 *   uint16_t pos (0 if first packet sent)
 *   blob     packet
 *   The last packet has the property that pos + blobSize == attrSize
 * receiver sends reply to transmitter
 *   uint8_t  status
 *   uint16_t transId (transaction ID for subsequent packets)
 * ... same packets are sent until entire attribute is sent
 *
 * SET RESPONSE
 * This packet is sent from the owner to the attribute daemon and from the attribute daemon to the
 * the requesting client. It is unsolicited, so it contains an opcode
 *   uint8_t opcode (AF_ATTR_OP_SET_REPLY)
 *   uint8_t status
 *   uint16_t opId
 *
 * SET
 * client transmits attribute to server
 * There are two cases for SET:
 *   client owns attribute
 *     if server receives attribute correctly it sends status == 0 otherwise it sends the corresponding status
 *     sends back a set response packet to owner
 *     if the attribute has its notify bit set AND there are interested clients
 *       then the server transmits attribute to interested listeners (opcode = AF_ATTR_OP_NOTIFY)
 *   client does not own attribute
 *     if server receives attribute correctly and the attribute is writable it
 *       transmits the attribute to the owner (opcode = AF_ATTR_OP_SET)
 *       owner sends back a set response packet
 *       server forward set response packet back to requester
 *     if the attribute has its notify bit set AND there are interested clients AND the set succeeded
 *       then the server transmits attribute to interested listeners (opcode = AF_ATTR_OP_NOTIFY)
 *
 * GET
 * client sends to server:
 *   uint8_t opcode (AF_ATTR_OP_GET)
 *   uint32_t attrId
 *   uint16_t opId (allows client to keep track of get requests)
 * server sends to owning client:
 *   uint8_t opcode (AF_ATTR_OP_GET)
 *   uint32_t attrId
 *   uint16_t opId
 * owning client replies to server
 *   uint8_t  status
 *   uint16_t opId
 *   if (status == 0 && opId == 0): blob value (fat get)
 * server sends to requesting client
 *   uint8_t  status
 *   uint16_t opId
 *   if (status == 0 && opId == 0): blob value (fat get)
 * if not a fat get, the owning client sends the transaction packets with the
 * AF_ATTR_OP_GET_REPLY opcode. The server forwards these packets to the requesting client
 * The opId matches the transaction packets back to the originating get packet
 *
 */

/* reference counted memory used for notification transactions */
/* if you need to free this in an exceptional case, use free() */
typedef struct {
    uint16_t refCount;
    uint16_t size;
    uint32_t attrId;
    uint8_t *value;
} attr_value_t;
attr_value_t *attr_value_create(uint32_t attributeId, uint16_t size);
void attr_value_inc_ref_count(attr_value_t *aValue);
void attr_value_dec_ref_count(attr_value_t *aValue);

/* defined trans as a void * to avoid compiler warning */
typedef void (*finished_callback_t)(int status, void *trans, void *context);
typedef int (*send_request_callback_t)(uint16_t clientId, uint8_t *buf, int bufSize, af_ipc_receive_callback_t receive, void *context, int timeoutMs);
typedef int (*send_response_callback_t)(uint32_t seqNum, uint8_t *buf, int bufSize);

/* This is not great */
typedef struct trans_tx_context_struct {
    send_request_callback_t sendCB;
    finished_callback_t finishedCB;
    void *finishedContext;
    uint16_t clientId; /* not used by attrd client */
} trans_tx_context_t;

typedef struct trans_rx_context_struct {
    struct trans_context_struct **head;
    struct event *timeoutEvent;
} trans_rx_context_t;

typedef struct trans_context_struct { // this structure does not support transmit retries
    uint8_t opcode;
    uint8_t pad;
    uint16_t pad2;
    uint16_t transId;
    uint16_t opId;
    uint16_t pos;
    attr_value_t *attrValue;
    union {
        trans_rx_context_t rxc;
        trans_tx_context_t txc;
    } u;
    struct trans_context_struct *next;
} trans_context_t;

/* allocate a pool of transactions */
int trans_pool_init(uint16_t maxTransactions);
/* get a transaction from the pool */
trans_context_t *trans_pool_alloc(void);
/* free a transaction to the pool */
void trans_pool_free(trans_context_t *t);
void trans_pool_deinit(void);

/* managing existing tranactions */

/* creates a new transaction for transmit or receive */
/* if head != NULL adds to the specified list */
/* if setId != 0 creates a new transaction ID otherwise sets ID to 0 */
void trans_add(trans_context_t **head, trans_context_t *t);
trans_context_t *trans_find_transaction_with_id(trans_context_t **head, uint16_t id);
/* removes transaction from specified list */
int trans_remove(trans_context_t **head, trans_context_t *trans);

/* receive an attribute packet
 *
 * allocates space for the trans_context and the attribute
 * returns the internal status as returned to the transmitter
 * returns a pointer to the received transaction
 * to check for the last packet, check if the received transaction has a timeout
 */
int trans_receive_packet(uint8_t *buf, int bufSize,
                         trans_context_t **trans, trans_context_t **head,
                         uint32_t seqNum,
                         struct event_base *base,
                         send_response_callback_t sendCB);

/* transmit an attribute
 *
 * assumes that the trans_context has been allocated and will persist.
 * you need to set up the finishedCB and sendCB before calling.
 * clientId is ignored in the attrd client
 */

int trans_transmit(uint16_t clientId, trans_context_t *trans, send_request_callback_t sendCB,
                   finished_callback_t finishedCB, void *finishedContext);


/* allocate and initialize a transaction based on an attribute */
/* returns -1 if an error occurs; errno will be set */
trans_context_t *trans_alloc (uint32_t attributeId, uint8_t opcode, uint8_t *value, int length);

/* cleans up memory associated with a transaction */
void trans_cleanup(trans_context_t *trans);

typedef struct client_op_context_struct {
    void *callback;
    void *context;
} client_op_context_t;

typedef struct server_get_op_context_struct {
    uint32_t clientSeqNum;
    uint16_t clientOpId;
    uint16_t clientId;
} server_get_op_context_t;

typedef struct server_set_op_context_struct {
    attr_value_t *attrValue;
    uint16_t clientOpId;
    uint16_t clientId;
} server_set_op_context_t;

typedef struct op_context_struct {
    uint16_t opId;
    uint16_t timeout;
    uint32_t attrId;
    struct event *timeoutEvent;
    union {
        client_op_context_t c;
        server_get_op_context_t sg;
        server_set_op_context_t ss;
    } u;
    struct op_context_struct *next;
} op_context_t;

int op_pool_init(uint16_t maxGets);
op_context_t *op_pool_alloc(void);
void op_pool_free(op_context_t *o);
void op_pool_deinit(void);

void op_cleanup(op_context_t **head, op_context_t *g);
op_context_t *op_find(op_context_t *head, uint16_t opId);

int get_create_rpc(op_context_t *g, uint32_t attrId, uint8_t *buf, int bufSize);
int set_reply_create_rpc(uint8_t status, uint16_t setId, uint8_t *buf, int bufSize);

/* allocate and add a timer for a timeout */
typedef void (*event_callback_t)(evutil_socket_t fd, short what, void *context);
struct event *allocate_and_add_timer(struct event_base *b, int timeoutMs, event_callback_t cb, void *context);

/* max blob size */
#define MAX_SEND_BLOB_SIZE (3968)

/* timeout for attribute set */
#define SET_TIMEOUT (5)

#endif // __AF_ATTR_PRV_H__

