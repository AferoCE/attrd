/*
 * file attr_script.h -- definitions for attribute script handler
 *
 * Copyright (c) 2016-2018 Afero, Inc. All rights reserved.
 *
 */

#ifndef __ATTR_SCRIPT_H__
#define __ATTR_SCRIPT_H__

#include <stdint.h>
#include <event2/event.h>
#include "attr_prv.h"

int script_parse_config(struct event_base *base);

/* called when the attribute daemon has been set up and should run the init scripts */
void script_init(void);

/* called when a notification occurs in case a script wants to handle the notification */
void script_notify(attr_value_t *v);

/* called when the owner of an attribute that is being set is unavailable */
int script_owner_set(uint16_t clientId, uint16_t setId, attr_value_t *v, void *a);

/* called when there is an attribute get request and the owner of said attribute is not available */
int script_get(uint32_t attrId, uint32_t seqNum, uint16_t getId);

#endif // __ATTR_SCRIPT_H__
