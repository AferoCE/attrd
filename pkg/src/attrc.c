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

#define ATTRD_SEND_ERR (-1)
#define ATTRD_SEND_OK  (0)

typedef enum {
    UINIT8,
    UINT16,
    UINT32,
    INT8,
    INT16,
    INT32,
    HEX,
    STR
} return_type_t;

uint32_t g_debugLevel = 2;
static int sDoSet = 0;
static int sDoGet = 0;
static int sDoWait = 0;

static return_type_t sArgType;

static uint8_t *sSetVal = NULL;
static uint32_t sAttrVal;

static int sStatus;

struct event_base *sEventBase = NULL;

static void on_set_finished(int status, uint32_t attributeId, void *context)
{
    if (status != AF_ATTR_STATUS_OK) {
        printf("status=%d\n", status);
        sStatus = status;
    }
    event_base_loopbreak(sEventBase);
}

static void on_notify(uint32_t attributeId, uint8_t *value, int length, void *context)
{
    switch (sArgType) {
        printf("Notify: ");
        case (STR):
            printf ("%s\n", (char *)value);
            break;
        case (UINIT8):
            printf ("%u\n", *(uint8_t *)value);
            break;
        case (UINT16):
            printf ("%d\n", *(uint16_t *)value);
            break;
        case (UINT32):
            printf ("%u\n", *(uint32_t *)value);
            break;
        case (INT8):
            printf ("%d\n", *(int8_t *)value);
            break;
        case (INT16):
            printf ("%d\n", *(int16_t *)value);
            break;
        case (INT32):
            printf ("%d\n", *(int32_t *)value);
            break;
        case (HEX):
            for (int i = 0; i<length; i++) {
                printf ("%02x", *((uint8_t *)value+i));
            }
            printf ("\n");
            break;
        default:
            fprintf (stderr, "No type");
            break;
    }
    event_base_loopbreak(sEventBase);
}

static void on_get_response(uint8_t status, uint32_t attributeId, uint8_t *value, int length, void *context)
{
    if (status != AF_ATTR_STATUS_OK) {
        fprintf (stderr,"status=%d\n", status);
        sStatus = status;
    } else {
        switch (sArgType) {
            case (STR):
                printf ("%s\n", (char *)value);
                break;
            case (UINIT8):
                printf ("%u\n", *(uint8_t *)value);
                break;
            case (UINT16):
                printf ("%d\n", *(uint16_t *)value);
                break;
            case (UINT32):
                printf ("%u\n", *(uint32_t *)value);
                break;
            case (INT8):
                printf ("%d\n", *(int8_t *)value);
                break;
            case (INT16):
                printf ("%d\n", *(int16_t *)value);
                break;
            case (INT32):
                printf ("%d\n", *(int32_t *)value);
                break;
            case (HEX):
                for (int i = 0; i<length; i++) {
                    printf ("%02x", *((uint8_t *)value+i));
                }
                printf ("\n");
                break;
            default:
                fprintf (stderr, "No type");
                break;
        }
    }
    event_base_loopbreak(sEventBase);
}

static void on_open(int status, void *context)
{
    if (status != AF_ATTR_STATUS_OK) {
        AFLOG_ERR("on_open_status:status=%d", status);
        event_base_loopbreak(sEventBase);
        return;
    }

    if (sDoGet) {
        status = af_attr_get (sAttrVal, on_get_response, NULL);
        if (status != AF_ATTR_STATUS_OK) {
            AFLOG_ERR("on_open_attr_get:status=%d", status);
        }
    }

    if (sDoSet && sSetVal != NULL) {
        status = af_attr_set (sAttrVal, sSetVal, strlen((const char *)sSetVal) + 1, on_set_finished, NULL);
        if (status != AF_ATTR_STATUS_OK) {
            AFLOG_ERR("on_open_attr_set:status=%d", status);
        }
    }
}


static
void usage()
{
    fprintf(stderr, "attrc [set <attribute> -<type> <value>] | [get <attribute> -<return_type>] | [wait <attribute> -<return_type>] \n");
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
is_param_type(const char *s)
{
    int size = 0;
    if (strlen(s) >= 2) {
        if (s[0] == '-') {
            switch (s[1]) {
                case 'u':
                    size = atoi(&s[2]);
                    switch (size) {
                       case (8):
                           sArgType = UINIT8;
                           break;
                       case (16):
                           sArgType = UINT16;
                           break;
                       case (32):
                           sArgType = UINT32;
                           break;
                       default:
                           return 0;
                           break;
                    }
                    break;

                case 'i':
                    size = atoi(&s[2]);
                    switch (size) {
                       case (8):
                           sArgType = INT8;
                           break;
                       case (16):
                           sArgType = INT16;
                           break;
                       case (32):
                           sArgType = INT32;
                           break;
                       default:
                           return 0;
                    }
                    break;
                case 's':
                    sArgType = STR;
		    break;

                case 'h':
                    sArgType = HEX;
		    break;

                default:
                    return 0;
            }
        }
    }
    return 1;
}

static int
param_type_value_match(const char *s, const char *t)
{
    switch (s[1]) {
        case ('i'):
            if (is_digits(t) == 1) {
               return 1;
            }
            break;

        case ('u'):
            if (is_digits(t) == 1) {
               return 1;
            }
            break;

        case ('s'):
            return 1;

        case ('h'):
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

static int
convert_input_val(const char * val)
{
    uint8_t *base;
    char *str_ptr;
    switch (sArgType) {

        case (UINIT8):
        {
            long int long_val = strtoul(val, &str_ptr, 10);
            if ((long_val > UINT8_MAX) || (long_val < 0)) {
                fprintf(stderr, "value outside of uint8_t range\n");
                return ATTRD_SEND_ERR;
            }
            uint8_t value = (uint8_t) long_val;
            base = malloc(sizeof(value));
            memcpy(base, &value, (sizeof(value)));
            break;
        }

        case (UINT16):
        {
            long int long_val = strtoul(val, &str_ptr, 10);
            if ((long_val > UINT16_MAX) || (long_val < 0)) {
                fprintf(stderr, "value outside of uint16_t range\n");
                return ATTRD_SEND_ERR;
            }
            uint16_t value = (uint16_t) long_val;
            base = malloc(sizeof(value));
            memcpy(base, &value, (sizeof(value)));
            break;
        }

        case (UINT32):
        {
            long int long_val = strtoul(val, &str_ptr, 10);
            if ((long_val > UINT32_MAX) || (long_val < 0)) {
                fprintf(stderr, "value outside uint32_t range\n");
                return ATTRD_SEND_ERR;
            }
            uint32_t value = (uint32_t) long_val;
            base = malloc(sizeof(value));
            memcpy(base, &value, (sizeof(value)));
            break;
        }

        case (INT8):
        {
            long int long_val = strtol(val, &str_ptr, 10);
            if ((long_val > INT8_MAX) || (long_val < INT8_MIN)) {
                fprintf(stderr, "value outside of int8_t range\n");
                return ATTRD_SEND_ERR;
            }
            int8_t value_signed = (int8_t) long_val;
            uint8_t value = *(uint8_t*)&value_signed;
            base = malloc(sizeof(value));
            memcpy(base, &value, (sizeof(value)));
            break;
        }

        case (INT16):
        {
            long int long_val = strtol(val, &str_ptr, 10);
            if ((long_val > INT16_MAX) || (long_val < INT16_MIN)) {
                fprintf(stderr, "value outside of int16_t range\n");
		return ATTRD_SEND_ERR;
	    }
	    int16_t value_signed = (int16_t) long_val;
	    uint16_t value = *(uint16_t*)&value_signed;
            base = malloc(sizeof(value));
	    memcpy(base, &value, (sizeof(value)));
            break;
        }

        case (INT32):
        {
            long int long_val = strtol(val, &str_ptr, 10);
            if ((long_val > INT32_MAX) || (long_val < INT32_MIN)) {
                fprintf(stderr, "value outside of int32_t range\n");
                return ATTRD_SEND_ERR;
            }
            int32_t value_signed = (int32_t) long_val;
            uint32_t value = *(uint32_t*)&value_signed;
            base = malloc(sizeof(value));
            memcpy(base, &value, (sizeof(value)));
            break;
        }

        case (STR):
        {
            int size = strlen(val) + 1;
            base = malloc(size);
            memcpy(base, val, size);
            break;
        }

        case (HEX):
        {
            const char *tmp = val;
            int l = strlen(tmp);
            if (l == 0 || (l % 2) != 0)
            {
                fprintf(stderr, "hex values must have an even number of digits in param");
                return ATTRD_SEND_ERR;
            }

            if (is_xdigits(tmp) == 0)
            {
                fprintf(stderr, "illegal hex digit in param");
                return ATTRD_SEND_ERR;
            }

            int len = l/2;
            base = malloc(len);

            for (l = 0; l < len; l++) {
                base[l] = hexnybble(tmp[l*2]) * 16 + hexnybble(tmp[l*2+1]);
            }
            break;
        }

        default:
            fprintf(stderr, "Illegal type");
            return ATTRD_SEND_ERR;
            break;
    }

    if (base == NULL)
    {
        fprintf(stderr, "Memory allocation error\n");
        return ATTRD_SEND_ERR; 
    }
    sSetVal = base;
    return ATTRD_SEND_OK; 
}

static int parse_params(int argc, char * argv[])
{
    int          i = 1;
    const char      *s; 

    while (i < argc) {
        s = argv[i];

        if ((strcmp(s,"wait") == 0) && (i+2 < argc)) {
            /* [wait <attr string> <return_type>] */
            if (is_param_type(argv[i+2]) == 0) {
                fprintf(stderr, "value arguement not -u[8|16|32] or -i[8|16|32] or -s or -h: %s\n", argv[i+2]);
                return ATTRD_SEND_ERR;
            }
            sDoWait = 1;
            return ATTRD_SEND_OK;

        } else if ((strcmp(s,"get") == 0) && (i+2 < argc)) {
            /* [get <attr string> <return_type>] */
            if (is_param_type(argv[i+2]) == 0) {
                fprintf(stderr, "value arguement not -u[8|16|32] or -i[8|16|32] or -s or -h: %s\n", argv[i+2]);
                return ATTRD_SEND_ERR;
            }
            sDoGet = 1;
            return ATTRD_SEND_OK;

        } else if ((strcmp(s,"set") == 0) && (i+3 < argc)) {
            /* [set <attr string> <val -u[8|16|32] or -i[8|16|32] or -s or -h>] */
            if (is_param_type(argv[i+2]) == 0) {
                fprintf(stderr, "value arguement not -u[8|16|32] or -i[8|16|32] or -s or -h: %s\n", argv[i+2]);
                return ATTRD_SEND_ERR;
            }

            if (param_type_value_match(argv[i+2],argv[i+3]) == 0) {
                fprintf(stderr, "value type does not match value arguement: %s\n", argv[i+3]);
                return ATTRD_SEND_ERR;
            }
            sDoSet = 1;
            return ATTRD_SEND_OK;

        } else {
            fprintf(stderr, "bad argument, not set, get, or wait: %s or bad number or args\n", argv[i]);
            return ATTRD_SEND_ERR;
        }
    }
    return ATTRD_SEND_ERR;
}

int main(int argc, char * argv[])
{
    int parse_ret = parse_params(argc, argv);

    if (parse_ret == ATTRD_SEND_ERR)
    {
        usage();
        exit(1);
    }
    if ((sDoWait) || (sDoGet)) {
        if (is_param_type(argv[2])== 0) {
            usage();
            exit(1);
        }

    } else if (sDoSet) {
        int status = convert_input_val(argv[4]);  // unsure if needed
        if (status == ATTRD_SEND_ERR) {
            usage();
            exit(1);
        }
    }

    sAttrVal = (uint32_t)atoi(argv[2]);

    openlog("attrc", LOG_PID, LOG_USER);

    evthread_use_pthreads();

    sEventBase = event_base_new();
    if (sEventBase == NULL) {
        printf("attrd:event_base_new::can't allocate event base");
        AFLOG_ERR("attrd:event_base_new::can't allocate event base");
        return(1);
    }

    af_attr_range_t r = { 10, 10 };

    int err = af_attr_open(sEventBase, "IPC.ATTRD",         //figure out what client name to use
                           (sDoWait ? 1 : 0), &r,
                           (sDoWait ? on_notify : NULL),        // notify callback
                           NULL,                                // owner set callback
                           NULL,                                // owner get callback
                           NULL,                                // close callback
                           on_open,                             // open callback
                           NULL);

    if (err != AF_ATTR_STATUS_OK) {
        printf("ipc_init_open:err=%d", err);
        AFLOG_ERR("ipc_init_open:err=%d", err);
        return -1;
    }

    event_base_dispatch(sEventBase);

    af_attr_close();

    event_base_free(sEventBase);
    if (sDoSet) {
        free(sSetVal);
    }

    closelog();

    if (sStatus) {
        return sStatus;
    }
}
