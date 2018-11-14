/*
 * attrc.c -- attribute client
 *
 * Copyright (c) 2016-2018 Afero, Inc. All rights reserved.
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <syslog.h>

#include "af_attr_client.h"
#include "af_log.h"
#include "value_formats.h"
#include "af_profile.h"

#define EDGE_ATTR_OWNER_NAME_PREFIX     "EDGED_"
#define EDGE_ATTR_OWNER_NAME_PREFIX_LEN (sizeof(EDGE_ATTR_OWNER_NAME_PREFIX)-1)

#define _AF_ATTR_OWNERDEF(_x) #_x

static char *sOwnerNames[] = {
    _AF_ATTR_OWNERS
};

#define _AF_ATTR_ATTRDEF(_attr_id_num,_attr_id_name,_attr_type,_attr_get_timeout,_attr_owner,_attr_flags) \
    { .name = #_attr_owner "_" #_attr_id_name , .id = _attr_id_num, .type = _attr_type, .owner = AF_ATTR_OWNER_##_attr_owner }

typedef struct {
    char *name;
    uint32_t id;
    af_attr_type_t type;
    af_attribute_owner_t owner;
} client_attr_t;

static client_attr_t sAttrs[] = {
    _AF_ATTR_ATTRIBUTES
};

#define _AF_ATTR_STATUS_DEF(_x) #_x

static char *sAttrStatus[] = {
    _AF_ATTR_STATUS_LIST
};

#undef _AF_ATTR_STATUS_DEF

#define ATTRC_ERR (-1)
#define ATTRC_OK  (0)

#define __OPERATIONS \
    __OP_DEF(INVALID,invalid) \
    __OP_DEF(SET,set) \
    __OP_DEF(GET,get) \
    __OP_DEF(WAIT,wait) \
    __OP_DEF(LIST,list) \
    __OP_DEF(OWNER_SET,owner_set) \

#define __OP_DEF(_x,_y) OP_##_x,

typedef enum {
    __OPERATIONS
    NUM_OPS
} op_type_t;

#undef __OP_DEF

#define __OP_DEF(_x,_y) #_y,

static char *sOpNames[] = {
    __OPERATIONS
};

#undef __OP_DEF

#ifdef BUILD_TARGET_DEBUG
uint32_t g_debugLevel = 2;
#else
uint32_t g_debugLevel = 1;
#endif

static op_type_t sOp = OP_INVALID;

static af_attr_type_t sArgType;
static uint32_t sAttrId;
static af_attribute_owner_t sOwner;

static uint8_t *sSetValue = NULL;
static int sSetValueLength = 0;

static int sStatus = 0;
static int sWaitTimeout = 0;

struct event_base *sEventBase = NULL;
struct event *sWaitTimeoutEvent = NULL;

static void on_set_finished(int status, uint32_t attributeId, void *context)
{
    if (status != AF_ATTR_STATUS_OK) {
        fprintf(stderr, "set failed: %s\n", sAttrStatus[status]);
        AFLOG_ERR("on_set_finished:status=%s", sAttrStatus[status]);
        sStatus = status;
    }
    event_base_loopbreak(sEventBase);
}

static void on_notify(uint32_t attributeId, uint8_t *value, int length, void *context)
{
    char *output = vf_alloc_and_convert_output_value(sArgType, value, length);
    printf ("%u %s\n", attributeId, output);
    free(output);
    event_base_loopbreak(sEventBase);
}

static void on_timeout(evutil_socket_t s, short what, void *context)
{
    AFLOG_ERR("on_timeout:timeout=%d", sWaitTimeout);
    sStatus = AF_ATTR_STATUS_TIMEOUT;
    event_base_loopbreak(sEventBase);
}

static void on_get_response(uint8_t status, uint32_t attributeId, uint8_t *value, int length, void *context)
{
    if (status != AF_ATTR_STATUS_OK) {
        AFLOG_ERR("on_get_response:status=%s", sAttrStatus[status]);
        fprintf (stderr,"get failed: %s\n", sAttrStatus[status]);
        sStatus = status;
    } else {
        char *output = vf_alloc_and_convert_output_value(sArgType, value, length);
        printf("%s\n", output);
        free(output);
    }
    event_base_loopbreak(sEventBase);
}

static void on_close(int status, void *context)
{
    AFLOG_ERR("on_close_status:status=%s", sAttrStatus[status]);
    fprintf(stderr, "unexpected close: %s\n", sAttrStatus[status]);
}

static void on_open(int status, void *context)
{
    if (status != AF_ATTR_STATUS_OK) {
        AFLOG_ERR("on_open_status:status=%s", sAttrStatus[status]);
        fprintf (stderr, "open failed: %s\n", sAttrStatus[status]);
        sStatus = status;
        return;
    }

    if (sOp == OP_GET) {
        status = af_attr_get (sAttrId, on_get_response, NULL);
        if (status != AF_ATTR_STATUS_OK) {
            AFLOG_ERR("on_open_attr_get:status=%d", status);
            fprintf(stderr, "get failed: %s\n", sAttrStatus[status]);
            sStatus = status;
            event_base_loopbreak(sEventBase);
        }
    }

    if (sOp == OP_SET) {
        status = af_attr_set (sAttrId, sSetValue, sSetValueLength, on_set_finished, NULL);
        if (status != AF_ATTR_STATUS_OK) {
            AFLOG_ERR("on_open_attr_set:status=%d", status);
            fprintf(stderr, "set failed: %s\n", sAttrStatus[status]);
            sStatus = status;
            event_base_loopbreak(sEventBase);
        }
    }

    if (sOp == OP_WAIT && sWaitTimeout) {
        sWaitTimeoutEvent = evtimer_new(sEventBase, on_timeout, NULL);
        if (sWaitTimeoutEvent) {
            struct timeval tv = { sWaitTimeout, 0 };
            event_add(sWaitTimeoutEvent, &tv);
        } else {
            fprintf(stderr, "create event failed: %s\n", strerror(errno));
        }
    }
}


static
void usage()
{
    fprintf(stderr, "attrc list | set | get | wait | owner_set <arguments>\n");
    fprintf(stderr, "   attrc list                          -- list attributes\n");
    fprintf(stderr, "   attrc set <attribute> <value>       -- set attribute value\n");
    fprintf(stderr, "   attrc get <attribute>               -- get attribute value\n");
    fprintf(stderr, "   attrc wait <attribute> [<timeout>]  -- wait for notification\n");
    fprintf(stderr, "   attrc owner_set <attribute> <value> -- spoof the owner and set an attribute\n");
    fprintf(stderr, "attribute can be specified by number, e.g., 51613 or by name, e.g., ATTRD_DEBUG_LEVEL\n");
    fprintf(stderr, "wait timeout is specified in seconds and defaults to no timeout\n");
}

static int
is_digits(const char *s)
{
    if (s) {
        if ((s[0] != '-') && (isdigit(s[0]) == 0)) {
            return 0;
        }
        s++;
        while (*s) {
            if (isdigit(*s++) == 0) {
                return 0;
            }
        }
        return 1;
    }
    return 0;
}

static int
is_xdigits(const char *s)
{
    if (s) {
        while (*s) {
            if (isxdigit(*s++) == 0) {
                return 0;
            }
        }
        return 1;
    }
    return 0;
}

static int
param_type_value_match(af_attr_type_t type, const char *t)
{
    switch (type) {
        case AF_ATTR_TYPE_SINT8:
        case AF_ATTR_TYPE_SINT16:
        case AF_ATTR_TYPE_SINT32:
            if (is_digits(t) == 1) {
               return 1;
            }
            break;

        case AF_ATTR_TYPE_UTF8S:
            return 1;

        case AF_ATTR_TYPE_BYTES:
            if (is_xdigits(t) == 1) {
               return 1;
            }
            break;

        default:
            return 1;
    }
    return 0;
}

static client_attr_t *parse_attribute_id(const char *arg)
{
    static client_attr_t sEdgeAttr;

    if (is_digits(arg)) {
        int attr = atoi(arg);

        for (int i = 0; i < sizeof(sAttrs) / sizeof(sAttrs[0]); i++) {
            if (attr == sAttrs[i].id) {
                return &sAttrs[i];
            }
        }
        /* check if it's an edge attribute */
        af_profile_attr_t *a = af_profile_get_attribute_with_id(attr);
        if (a) {
            sEdgeAttr.id = attr;   /* we don't need the number anymore */
            sEdgeAttr.name = NULL; /* we don't need the name anymore */
            sEdgeAttr.type = a->type;
            sEdgeAttr.owner = AF_ATTR_OWNER_EDGED;
            return &sEdgeAttr;
        }
    } else {
        // check for edge attributes
        if (!strncmp(arg, EDGE_ATTR_OWNER_NAME_PREFIX, EDGE_ATTR_OWNER_NAME_PREFIX_LEN) &&
            is_digits(&arg[EDGE_ATTR_OWNER_NAME_PREFIX_LEN])) {
            int num = atoi(&arg[EDGE_ATTR_OWNER_NAME_PREFIX_LEN]);
            if (num) {
                af_profile_attr_t *a = af_profile_get_attribute_with_id(num);
                if (a) {
                    sEdgeAttr.id = num;    /* we don't need the number anymore */
                    sEdgeAttr.name = NULL; /* we don't need the name anymore */
                    sEdgeAttr.type = a->type;
                    return &sEdgeAttr;
                }
            }
        }

        // check for the other attributes
        for (int i = 0; i < sizeof(sAttrs) / sizeof(sAttrs[0]); i++) {
            if (!strcmp(sAttrs[i].name, arg)) {
                return &sAttrs[i];
            }
        }
    }

    fprintf(stderr, "Attribute %s not found\n", arg);
    return NULL;
}

static int parse_params(int argc, char * argv[])
{
    /* have already verified that argc > 1 */
    switch (sOp) {
        case OP_WAIT :
            if (argc > 2) {
                client_attr_t *attr = parse_attribute_id(argv[2]);
                if (!attr) {
                    return ATTRC_ERR;
                }
                sAttrId = attr->id;
                sArgType = attr->type;
                if (argc > 3) {
                    if (is_digits(argv[3])) {
                        sWaitTimeout = atoi(argv[3]);
                    } else {
                        return ATTRC_ERR;
                    }
                }
                return ATTRC_OK;
            }
            break;
        case OP_GET :
            if (argc > 2) {
                client_attr_t *attr = parse_attribute_id(argv[2]);
                if (!attr) {
                    return ATTRC_ERR;
                }
                sAttrId = attr->id;
                sArgType = attr->type;
                return ATTRC_OK;
            }
            break;
        case OP_OWNER_SET :
        case OP_SET :
            if (argc > 2) {
                client_attr_t *attr = parse_attribute_id(argv[2]);
                if (!attr) {
                    return ATTRC_ERR;
                }
                sAttrId = attr->id;
                sOwner = attr->owner;
                af_attr_type_t argType = attr->type;
                if (argc == 3 && (argType == AF_ATTR_TYPE_BYTES || argType == AF_ATTR_TYPE_UTF8S)) {
                    sSetValue = vf_alloc_and_convert_input_value(argType, "", &sSetValueLength);
                    if (sSetValue == NULL) {
                        return ATTRC_ERR;
                    }
                    return ATTRC_OK;
                } else if (argc > 3) {
                    if (param_type_value_match(argType, argv[3]) == 0) {
                        fprintf(stderr, "value type does not match value argument: %s\n", argv[3]);
                        return ATTRC_ERR;
                    }

                    sSetValue = vf_alloc_and_convert_input_value(argType, argv[3], &sSetValueLength);
                    if (sSetValue == NULL) {
                        return ATTRC_ERR;
                    }
                    return ATTRC_OK;
                }
            }
            break;
        default :
            break;
    }
    return ATTRC_ERR;
}

#define IPC_NAME_PREFIX "IPC."

int main(int argc, char * argv[])
{
    int parse_ret = ATTRC_OK;

    int numEdgeAttrs = af_profile_load(NULL);

    sOp = OP_INVALID;

    if (argc > 1) {
        for (int i = OP_INVALID + 1 ; i < NUM_OPS; i++) {
            if (!strncmp(argv[1], sOpNames[i], strlen(argv[1]))) {
                sOp = i;
                break;
            }
        }
        if (sOp == OP_INVALID) {
            usage();
            AFLOG_ERR("unknown_operation:op=%s", argv[1]);
            return AF_ATTR_STATUS_BAD_PARAM;
        }
    } else {
        usage();
        AFLOG_ERR("no_arguments");
        return AF_ATTR_STATUS_BAD_PARAM;
    }

    if (sOp == OP_LIST) {
        for (int i = 0; i < numEdgeAttrs; i++) {
            af_profile_attr_t *a = af_profile_get_attribute_at_index(i);
            if (a && a->attr_id >= AF_ATTR_EDGE_START && a->attr_id <= AF_ATTR_EDGE_END) {
                printf("%5d EDGED_%d %s\n", a->attr_id, a->attr_id, vf_get_name_for_type(a->type));
            }
        }
        for (int i = 0; i < sizeof(sAttrs)/sizeof(sAttrs[0]); i++) {
            printf("%5d %s %s\n", sAttrs[i].id, sAttrs[i].name, vf_get_name_for_type(sAttrs[i].type));
        }
        exit(0);
    } else {
        parse_ret = parse_params(argc, argv);
    }

    if (parse_ret == ATTRC_ERR) {
        usage();
        return AF_ATTR_STATUS_BAD_PARAM;
    }

    openlog("attrc", LOG_PID, LOG_USER);

    evthread_use_pthreads();

    sEventBase = event_base_new();
    if (sEventBase == NULL) {
        printf("attrd:event_base_new::can't allocate event base");
        AFLOG_ERR("attrd:event_base_new::can't allocate event base");
        return AF_ATTR_STATUS_NO_SPACE;
    }

    af_attr_range_t r;
    if (sOp == OP_WAIT) {
        r.first = r.last = sAttrId;
    }

    char ownerName[AF_ATTR_OWNER_NAME_SIZE + 10];

    if (sOp == OP_OWNER_SET) {
        sprintf(ownerName, "ATTRC.%s", sOwnerNames[sOwner]);
        /* from here on out, it's just a plain set */
        sOp = OP_SET;
    } else {
        strcpy(ownerName, "IPC.ATTRC");
    }

    int err = af_attr_open(sEventBase, ownerName,
                           (sOp == OP_WAIT ? 1 : 0), &r,
                           (sOp == OP_WAIT ? on_notify : NULL), // notify callback
                           NULL,                                // owner set callback
                           NULL,                                // owner get callback
                           on_close,                            // close callback
                           on_open,                             // open callback
                           NULL);

    if (err != AF_ATTR_STATUS_OK) {
        printf("ipc_init_open:err=%d", err);
        AFLOG_ERR("ipc_init_open:err=%d", err);
        return err;
    }

    event_base_dispatch(sEventBase);

    af_attr_close();

    if (sWaitTimeoutEvent) {
        event_free(sWaitTimeoutEvent);
        sWaitTimeoutEvent = NULL;
    }

    event_base_free(sEventBase);
    if (sSetValue) {
        free(sSetValue);
    }

    af_profile_free();

    closelog();

    if (sStatus) {
        return sStatus;
    }
}
