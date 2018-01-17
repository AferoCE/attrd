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

#define EDGE_ATTR_OWNER_NAME_PREFIX     "EDGE_ATTR_"
#define EDGE_ATTR_OWNER_NAME_PREFIX_LEN (sizeof(EDGE_ATTR_OWNER_NAME_PREFIX)-1)

#define _AF_ATTR_ATTRDEF(_attr_id_num,_attr_id_name,_attr_type,_attr_get_timeout,_attr_owner,_attr_flags) { #_attr_owner "_" #_attr_id_name , _attr_id_num }

typedef struct {
    char *name;
    uint32_t id;
} attrc_t;

static attrc_t sAttrs[] = {
    _AF_ATTR_ATTRIBUTES
};

#define _AF_ATTR_STATUS_DEF(_x) #_x

static char *sAttrStatus[] = {
    _AF_ATTR_STATUS_LIST
};

#undef _AF_ATTR_STATUS_DEF

#define ATTRC_ERR (-1)
#define ATTRC_OK  (0)

typedef enum {
    OP_INVALID = 0,
    OP_SET,
    OP_GET,
    OP_WAIT
} op_type_t;

uint32_t g_debugLevel = 2;
static op_type_t sOp = OP_INVALID;

static value_format_t sArgType;
static uint32_t sAttrId;

static uint8_t *sSetValue = NULL;
static int sSetValueLength = 0;

static int sStatus = 0;
static char sAttrOwner[32];

struct event_base *sEventBase = NULL;

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
    printf ("%u ", attributeId);
    char *output = vf_alloc_and_convert_output_value(sArgType, value, length);
    printf ("%s\n", output);
    free(output);
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
}


static
void usage()
{
    fprintf(stderr, "attrc [-s <name>] set | get | wait <arguments>\n");
    fprintf(stderr, "   attrc set <attribute> <value> [<type>]\n");
    fprintf(stderr, "   attrc get <attribute> [<return_type>]\n");
    fprintf(stderr, "   attrc wait <attribute> [<return_type>]\n");
    fprintf(stderr, "   attribute can be specified by number, e.g., 51613 or by name, e.g., ATTRD_DEBUG_LEVEL\n");
    fprintf(stderr, "   type can be one of i8, i16, i32, u8, u16, u32, h, or s. Type defaults to h\n");
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
param_type_value_match(value_format_t type, const char *t)
{
    switch (type) {
        case VALUE_FORMAT_INT8:
        case VALUE_FORMAT_INT16:
        case VALUE_FORMAT_INT32:
        case VALUE_FORMAT_UINT8:
        case VALUE_FORMAT_UINT16:
        case VALUE_FORMAT_UINT32:
            if (is_digits(t) == 1) {
               return 1;
            }
            break;

        case VALUE_FORMAT_STRING:
            return 1;

        case VALUE_FORMAT_HEX:
            if (is_xdigits(t) == 1) {
               return 1;
            }
            break;

        default:
            return 1;
    }
    return 0;
}

static int parse_attribute_id(const char *arg)
{
	int i, attr;

    if (is_digits(arg)) {
        attr = atoi(arg);
        if ((attr >= AF_ATTR_EDGE_START) && (attr <= AF_ATTR_EDGE_END)) {
            return attr;
        }

        for (i = 0; i < sizeof(sAttrs) / sizeof(sAttrs[0]); i++) {
            if (attr == sAttrs[i].id) {
                return attr;
            }
        }
    } else {
        // handle the edge attributes (MCU attributes) first
        int len = strlen(arg);
        if (!strncmp(arg, EDGE_ATTR_OWNER_NAME_PREFIX, EDGE_ATTR_OWNER_NAME_PREFIX_LEN)) {
            if (len > EDGE_ATTR_OWNER_NAME_PREFIX_LEN) {
                sscanf(&arg[EDGE_ATTR_OWNER_NAME_PREFIX_LEN], "%d", &attr);
                if ((attr >= AF_ATTR_EDGE_START) && (attr <= AF_ATTR_EDGE_END)) {
                    return attr;
                }
		    }

            // if it gets here, then an error has occurred
            goto err_exit;
        }

        // check for the other attributes
        for (i = 0; i < sizeof(sAttrs) / sizeof(sAttrs[0]); i++) {
            if (!strcmp(sAttrs[i].name, arg)) {
                return sAttrs[i].id;
            }
        }
    }

err_exit:
    fprintf(stderr, "Attribute %s not found\n", arg);
    return -1;
}

static int parse_params(int argc, char * argv[])
{
    if (argc > 1) {
        if (!strncmp(argv[1], "wait", strlen(argv[1])) && argc > 2) {
            int id = parse_attribute_id(argv[2]);
            if (id < 0) {
                return ATTRC_ERR;
            }
            sAttrId = id;
            if (argc > 3) {
                sArgType = vf_get_format_for_name(argv[3]);
                if (sArgType == VALUE_FORMAT_UNKNOWN) {
                    return ATTRC_ERR;
                }
            } else {
                sArgType = VALUE_FORMAT_HEX;
            }
            sOp = OP_WAIT;
            return ATTRC_OK;

        } else if (!strncmp(argv[1], "get", strlen(argv[1])) && argc > 2) {
            int id = parse_attribute_id(argv[2]);
            if (id < 0) {
                return ATTRC_ERR;
            }
            sAttrId = id;
            if (argc > 3) {
                sArgType = vf_get_format_for_name(argv[3]);
                if (sArgType == VALUE_FORMAT_UNKNOWN) {
                    return ATTRC_ERR;
                }
            } else {
                sArgType = VALUE_FORMAT_HEX;
            }
            sOp = OP_GET;
            return ATTRC_OK;

        } else if (!strncmp(argv[1], "set", strlen(argv[1])) && argc > 2) {
            int id = parse_attribute_id(argv[2]);
            if (id < 0) {
                return ATTRC_ERR;
            }
            sAttrId = id;
            if (argc > 3) {
                int argType = VALUE_FORMAT_HEX;
                if (argc > 4) {
                    argType = vf_get_format_for_name(argv[4]);
                    if (argType == VALUE_FORMAT_UNKNOWN) {
                        return ATTRC_ERR;
                    }
                }
                if (param_type_value_match(argType, argv[3]) == 0) {
                    fprintf(stderr, "value type does not match value argument: %s\n", argv[3]);
                    return ATTRC_ERR;
                }

                sSetValue = vf_alloc_and_convert_input_value(argType, argv[3], &sSetValueLength);
                if (sSetValue == NULL) {
                    return ATTRC_ERR;
                }
                sOp = OP_SET;
                return ATTRC_OK;
            }
        }
    }
    return ATTRC_ERR;
}

#define IPC_NAME_PREFIX "IPC."

int main(int argc, char * argv[])
{
    int parse_ret = ATTRC_OK;

    strcpy(sAttrOwner, "IPC.ATTRC");

    if (argc > 1) {
        if (!strcmp(argv[1], "-s")) {
            if (argc > 2) {
                strcpy(sAttrOwner, IPC_NAME_PREFIX);
                strncat(sAttrOwner, argv[2], sizeof(sAttrOwner) - sizeof(IPC_NAME_PREFIX));
                parse_ret = parse_params(argc - 2, &argv[2]);
            } else {
                usage();
                return AF_ATTR_STATUS_BAD_PARAM;
            }
        } else {
            parse_ret = parse_params(argc, argv);
        }
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

    int err = af_attr_open(sEventBase, sAttrOwner,
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

    event_base_free(sEventBase);
    if (sSetValue) {
        free(sSetValue);
    }

    closelog();

    if (sStatus) {
        return sStatus;
    }
}
