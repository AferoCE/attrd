/*
 * file af_attr_client.h -- Attribute daemon client API
 *
 * Copyright (c) 2016 Afero, Inc. All rights reserved.
 *
 */
#ifndef __AF_ATTR_CLIENT_H__
#define __AF_ATTR_CLIENT_H__

#include "af_attr_def.h"

#define AF_ATTR_MAX_LISTEN_RANGES 10

/* status codes */
enum {
    AF_ATTR_STATUS_OK = 0,
    AF_ATTR_STATUS_UNSPECIFIED,           // 1
    AF_ATTR_STATUS_TOO_MANY_RANGES,       // 2
    AF_ATTR_STATUS_OWNER_NOT_AVAILABLE,   // 3
    AF_ATTR_STATUS_BAD_TLV,               // 4
    AF_ATTR_STATUS_NO_SPACE,              // 5
    AF_ATTR_STATUS_BAD_DATA,              // 6
    AF_ATTR_STATUS_TOO_MANY_TRANSACTIONS, // 7
    AF_ATTR_STATUS_TRANSACTION_NOT_FOUND, // 8
    AF_ATTR_STATUS_BAD_PARAM,             // 9
    AF_ATTR_STATUS_NOT_WRITABLE,          // 10
    AF_ATTR_STATUS_NOT_OPEN,              // 11
    AF_ATTR_STATUS_ATTR_ID_NOT_FOUND,     // 12
    AF_ATTR_STATUS_NO_DAEMON,             // 13
    AF_ATTR_STATUS_TIMEOUT,               // 14
    AF_ATTR_STATUS_SET_REJECT_BUSY,       // 15
    AF_ATTR_STATUS_NOT_IMPLEMENTED,       // 16 -- consider this an internal error
    AF_ATTR_STATUS_MAX
};

/*
  af_attr_notify_callback

  Informs the client that an attribute that it is interested in has been modified
*/
typedef void (*af_attr_notify_callback_t) (uint32_t attributeId, uint8_t *value, int length, void *context);

/*
  af_attr_set_request_callback

  Informs the client that another client has attempted to set an attribute that it owns.
  Returns the status of the set. For example, the set could fail because the client is
  busy modifying the same attribute.
*/
typedef int (*af_attr_set_request_callback_t) (uint32_t attributeId, uint8_t *value, int length, void *context);

/*
  af_attr_get_request_callback

  Informs the client that someone has requested an attribute that it owns. The
  callback can immediately call af_attr_send_get_response or call it later.
*/
typedef void (*af_attr_get_request_callback_t) (uint32_t attributeId, uint16_t getId, void *context);

/*
  af_attr_status_callback

  Informs the client of the success or failure of an open or close operation.
*/
typedef void (*af_attr_status_callback_t) (int status, void *context);

typedef struct {
	uint32_t first;
	uint32_t last;
} af_attr_range_t;

/* af_attr_open
 *
 * Opens a connection to the server with the specified client name. The listenRanges
 * parameter specifies an array of ranges of attribute IDs for which the client wants
 * attribute change notifications, and the numListenRanges parameter specifies the
 * number of ranges in listenRanges list.
 *
 * Five callbacks are specified:
 *   notifyCb -- an attribute the client is interested in has changed
 *   ownerSetCb -- another client has changed an attribute this client owns
 *   getReqCb -- another client has requested an attribute this client owns
 *   closeCb -- the attribute client library has closed unexpectedly
 *   openCb -- the attribute client library either opened successfully or failed to open
 *
 * The five callbacks use the same specified context.
 *
 * Returns AF_ATTR_STATUS_OK if the open succeeds or an error code on failure.
 */
int af_attr_open (struct event_base *base,
                  char *clientName,
                  uint16_t numListenRanges, af_attr_range_t *listenRanges,
                  af_attr_notify_callback_t notifyCb,
                  af_attr_set_request_callback_t ownerSetCb,
                  af_attr_get_request_callback_t getReqCb,
                  af_attr_status_callback_t closeCb,
                  af_attr_status_callback_t openCb,
                  void *context);

typedef void (*af_attr_set_response_callback_t)(int status, uint32_t attributeId, void *setContext);

/* af_attr_set
 *
 * Sets the attribute with the specified ID to the specified value. All
 * attributes are byte arrays with a length. This means that the attribute value
 * is not necessarily a null terminated string.
 *
 * If the client is the owner of the attribute and the notify bit is set in the
 * attribute flags, the change is propagated to the attribute daemon and any
 * interested listeners.
 *
 * If the client is not the owner of the attribute, the setting is propagated to
 * the attribute daemon and then to the owner. If the notify bit is set in the
 * attribute flags, the change is propagated to the interested listeners too.
 */
int af_attr_set (uint32_t attributeId, uint8_t *value, int length, af_attr_set_response_callback_t setCB, void *setContext);

/* af_attr_get
 *
 * Gets the attribute with the specified ID. This is an asynchronous call, and the
 * result is returned using the specified callback function. This function
 * requests the attribute value from the attribute daemon, who forwards the request to
 * the client that owns the attribute. The owner returns the value of the attribute
 * to the attribute daemon, who returns it to the requesting client via the call-
 * back.
 */

typedef void (*af_attr_get_response_callback_t)(uint8_t status, uint32_t attributeId, uint8_t *value, int length, void *context);

int af_attr_get (uint32_t attributeId, af_attr_get_response_callback_t cb, void *context);

/* af_attr_send_get_response
 *
 * Sends a response to a get request received with the getReqCb.
 * This function sends the response to the attribute daemon, who forwards it to the
 * requesting client.
 */
int af_attr_send_get_response (int status, uint16_t getId, uint8_t *value, int length);

/* af_attr_close
 *
 * Closes the client's connection to the daemon and frees internal resources associated
 * with that connection. The close callback will not be called if this function is called.
 */
void af_attr_close (void);

#endif // __AF_ATTR_CLIENT_H__
