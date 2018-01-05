/*
 * Copyright (c) 2016 Afero, Inc. All rights reserved.
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

#define _ATTRDEF(_attr_id_num,_attr_id_name,_attr_type,_attr_get_timeout,_attr_owner,_attr_flags) { #_attr_owner "_" #_attr_id_name , _attr_id_num }

typedef struct {
    char *name;
    uint32_t id;
} attrc_t;

static attrc_t sAttrs[] = {
    _ATTRIBUTES
};

#define _ATTR_STATUS_DEF(_x) #_x

static char *sAttrStatus[] = {
    _ATTR_STATUS_LIST
};

#define ATTRC_ERR (-1)
#define ATTRC_OK  (0)

typedef enum {
    ARG_TYPE_INVALID = 0,
    ARG_TYPE_UINT8,
    ARG_TYPE_UINT16,
    ARG_TYPE_UINT32,
    ARG_TYPE_INT8,
    ARG_TYPE_INT16,
    ARG_TYPE_INT32,
    ARG_TYPE_HEX,
    ARG_TYPE_STRING
} arg_type_t;

typedef enum {
    OP_INVALID = 0,
    OP_SET,
    OP_GET,
    OP_WAIT
} op_type_t;

uint32_t g_debugLevel = 2;
static op_type_t sOp = OP_INVALID;

static arg_type_t sArgType;
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


static void print_value(uint8_t *value, int length, arg_type_t argType)
{
    switch (argType) {
        case ARG_TYPE_STRING:
            printf ("\"%s\"", (char *)value);
            break;
        case ARG_TYPE_UINT8:
            printf ("%u", *(uint8_t *)value);
            break;
        case ARG_TYPE_UINT16:
            printf ("%d", af_attr_get_uint16(value));
            break;
        case ARG_TYPE_UINT32:
            printf ("%u", af_attr_get_uint32(value));
            break;
        case ARG_TYPE_INT8:
            printf ("%d", *(int8_t *)value);
            break;
        case ARG_TYPE_INT16:
            printf ("%d", af_attr_get_int16(value));
            break;
        case ARG_TYPE_INT32:
            printf ("%d", af_attr_get_int32(value));
            break;
        case ARG_TYPE_HEX:
            for (int i = 0; i<length; i++) {
                printf ("%02x", *((uint8_t *)value+i));
            }
            break;
        default:
            fprintf (stderr, "No type");
            break;
    }
}

static void on_notify(uint32_t attributeId, uint8_t *value, int length, void *context)
{
    printf ("%u ", attributeId);
    print_value(value, length, sArgType);
    printf ("\n");
    event_base_loopbreak(sEventBase);
}

static void on_get_response(uint8_t status, uint32_t attributeId, uint8_t *value, int length, void *context)
{
    if (status != AF_ATTR_STATUS_OK) {
        AFLOG_ERR("on_get_response:status=%s", sAttrStatus[status]);
        fprintf (stderr,"get failed: %s\n", sAttrStatus[status]);
        sStatus = status;
    } else {
        print_value(value, length, sArgType);
        printf("\n");
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

static arg_type_t
param_type(const char *s)
{
    int size = 0;
    int retVal = ARG_TYPE_INVALID;
    if (strlen(s) >= 1) {
        switch (s[0]) {
            case 'u':
                size = atoi(&s[1]);
                switch (size) {
                    case 8:
                        retVal = ARG_TYPE_UINT8;
                        break;
                    case 16:
                        retVal = ARG_TYPE_UINT16;
                        break;
                    case 32:
                        retVal = ARG_TYPE_UINT32;
                        break;
                }
                break;

            case 'i':
                size = atoi(&s[1]);
                switch (size) {
                    case 8:
                        retVal = ARG_TYPE_INT8;
                        break;
                    case 16:
                        retVal = ARG_TYPE_INT16;
                        break;
                    case 32:
                        retVal = ARG_TYPE_INT32;
                        break;
                }
                break;

            case 's':
                retVal = ARG_TYPE_STRING;
                break;

            case 'h':
                retVal = ARG_TYPE_HEX;
                break;

            default:
                break;
        }
    }
    if (retVal == ARG_TYPE_INVALID) {
        fprintf(stderr, "invalid argument type %s\n", s);
    }
    return retVal;
}

static int
param_type_value_match(arg_type_t type, const char *t)
{
    switch (type) {
        case ARG_TYPE_INT8:
        case ARG_TYPE_INT16:
        case ARG_TYPE_INT32:
            if (is_digits(t) == 1) {
               return 1;
            }
            break;

        case ARG_TYPE_UINT8:
        case ARG_TYPE_UINT16:
        case ARG_TYPE_UINT32:
            if (is_digits(t) == 1) {
               return 1;
            }
            break;

        case ARG_TYPE_STRING:
            return 1;

        case ARG_TYPE_HEX:
            if (is_xdigits(t) == 1) {
               return 1;
            }
            break;

        default:
            return 1;
    }
    return 0;
}

static uint8_t
hexnybble(char c)
{
    if (c >= '0' && c <= '9') {
        c = c - '0';
    } else if (c >= 'a' && c <= 'f') {
        c = c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        c = c - 'A' + 10;
    } else {
        c = 0;
    }
    return (uint8_t)c;
}

static uint8_t *
convert_input_value(arg_type_t type, const char * val, int *lengthP)
{
    uint8_t *setValue = NULL;

    if (lengthP == NULL) {
        return NULL;
    }

    switch (type) {

        case ARG_TYPE_UINT8:
        {
            int32_t long_val = strtoul(val, NULL, 10);
            if ((long_val > UINT8_MAX) || (long_val < 0)) {
                fprintf(stderr, "value outside of uint8_t range\n");
                return NULL;
            }
            uint8_t value = (uint8_t) long_val;
            setValue = malloc(sizeof(value));
            if (setValue == NULL)
            {
                fprintf(stderr, "Memory allocation error\n");
                return NULL;
            }
            memcpy(setValue, &value, (sizeof(value)));
            *lengthP = sizeof(uint8_t);
            break;
        }

        case ARG_TYPE_UINT16:
        {
            int32_t long_val = strtol(val, NULL, 10);
            if ((long_val > UINT16_MAX) || (long_val < 0)) {
                fprintf(stderr, "value outside of uint16_t range\n");
                return NULL;
            }
            setValue = malloc(sizeof(uint16_t));
            if (setValue == NULL)
            {
                fprintf(stderr, "Memory allocation error\n");
                return NULL;
            }
            af_attr_store_uint16(setValue, (uint16_t)long_val);
            *lengthP = sizeof(uint16_t);
            break;
        }

        case ARG_TYPE_UINT32:
        {
            errno = 0;
            uint32_t long_val = strtoul(val, NULL, 10);
            if (val[0] == '-' || (long_val == UINT32_MAX && errno == ERANGE)) {
                fprintf(stderr, "value outside of uint32_t range\n");
                return NULL;
            }
            setValue = malloc(sizeof(uint32_t));
            if (setValue == NULL) {
                fprintf(stderr, "Memory allocation error\n");
                return NULL;
            }
            af_attr_store_uint32(setValue, long_val);
            *lengthP = sizeof(uint32_t);
            break;
        }

        case ARG_TYPE_INT8:
        {
            int32_t long_val = strtol(val, NULL, 10);
            if ((long_val > INT8_MAX) || (long_val < INT8_MIN)) {
                fprintf(stderr, "value outside of int8_t range\n");
                return NULL;
            }
            setValue = malloc(sizeof(int8_t));
            if (setValue == NULL)
            {
               fprintf(stderr, "Memory allocation error\n");
               return NULL;
            }
            int8_t value = (int8_t)long_val;
            memcpy(setValue, &value, sizeof(value));
            *lengthP = sizeof(int8_t);
            break;
        }

        case ARG_TYPE_INT16:
        {
            int32_t long_val = strtol(val, NULL, 10);
            if ((long_val > INT16_MAX) || (long_val < INT16_MIN)) {
                fprintf(stderr, "value outside of int16_t range\n");
                return NULL;
            }
            setValue = malloc(sizeof(int16_t));
            if (setValue == NULL)
            {
                fprintf(stderr, "Memory allocation error\n");
                return NULL;
            }
            af_attr_store_int16(setValue, (int16_t)long_val);
            *lengthP = sizeof(int16_t);
            break;
        }

        case ARG_TYPE_INT32:
        {
            int32_t long_val = strtol(val, NULL, 10);
            if ((long_val == INT32_MIN || long_val == INT32_MAX) && errno == ERANGE) {
                fprintf(stderr, "value outside of int32_t range\n");
                return NULL;
            }
            setValue = malloc(sizeof(int32_t));
            if (setValue == NULL)
            {
                fprintf(stderr, "Memory allocation error\n");
                return NULL;
            }
            af_attr_store_int32(setValue, long_val);
            *lengthP = sizeof(int32_t);
            break;
        }

        case ARG_TYPE_STRING:
        {
            int size = strlen(val) + 1;
            setValue = malloc(size);
            if (setValue == NULL)
            {
                fprintf(stderr, "Memory allocation error\n");
                return NULL;
            }
            memcpy(setValue, val, size);
            *lengthP = size;
            break;
        }

        case ARG_TYPE_HEX:
        {
            const char *tmp = val;
            int l = strlen(tmp);
            if (l == 0 || (l % 2) != 0)
            {
                fprintf(stderr, "hex values must have an even number of digits in param\n");
                return NULL;
            }

            if (is_xdigits(tmp) == 0)
            {
                fprintf(stderr, "illegal hex digit in param\n");
                return NULL;
            }

            int len = l/2;
            setValue = malloc(len);
            if (setValue == NULL)
            {
                fprintf(stderr, "Memory allocation error\n");
                return NULL;
            }

            for (l = 0; l < len; l++) {
                setValue[l] = hexnybble(tmp[l*2]) * 16 + hexnybble(tmp[l*2+1]);
            }
            *lengthP = len;
            break;
        }

        default:
            fprintf(stderr, "Illegal type");
            return NULL;
            break;
    }

    return setValue;
}

static int parse_attribute_id(const char *arg)
{
	int i, attr;

    if (is_digits(arg)) {
        attr = atoi(arg);
        if ((attr >= EDGE_ATTR_START) && (attr <= EDGE_ATTR_END)) {
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
                if ((attr >= EDGE_ATTR_START) && (attr <= EDGE_ATTR_END)) {
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
                sArgType = param_type(argv[3]);
                if (sArgType == ARG_TYPE_INVALID) {
                    return ATTRC_ERR;
                }
            } else {
                sArgType = ARG_TYPE_HEX;
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
                sArgType = param_type(argv[3]);
                if (sArgType == ARG_TYPE_INVALID) {
                    return ATTRC_ERR;
                }
            } else {
                sArgType = ARG_TYPE_HEX;
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
                int argType = ARG_TYPE_HEX;
                if (argc > 4) {
                    argType = param_type(argv[4]);
                    if (argType == ARG_TYPE_INVALID) {
                        return ATTRC_ERR;
                    }
                }
                if (param_type_value_match(argType, argv[3]) == 0) {
                    fprintf(stderr, "value type does not match value argument: %s\n", argv[3]);
                    return ATTRC_ERR;
                }

                sSetValue = convert_input_value(argType, argv[3], &sSetValueLength);
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
