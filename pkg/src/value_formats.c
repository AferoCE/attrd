/*
 * file value_formats.h -- definitions for value formats
 *
 * Copyright (c) 2016-2018 Afero, Inc. All rights reserved.
 *
 */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include "value_formats.h"
#include "attr_prv.h"
#include "af_log.h"

typedef struct {
    af_attr_type_t type;
    int size;
    char *name;
} attr_size_t;

#define _AF_ATTR_TYPE_DEFN(_num,_name,_size) { .type=AF_ATTR_TYPE_##_name, .size=_size, .name=#_name }

attr_size_t attr_sizes[] = {
    _AF_ATTR_TYPES
};

#define NUM_ATTR_TYPES (sizeof(attr_sizes)/sizeof(attr_sizes[0]))

int vf_get_size_for_type(af_attr_type_t type)
{
    for (int i=0; i < NUM_ATTR_TYPES; i++) {
        if (attr_sizes[i].type == type) {
            return attr_sizes[i].size;
        }
    }
    return -1;
}

char *vf_get_name_for_type(af_attr_type_t type)
{
    if (type == AF_ATTR_TYPE_UNKNOWN) {
        return NULL;
    }

    for (int i=0; i < NUM_ATTR_TYPES; i++) {
        if (attr_sizes[i].type == type) {
            return attr_sizes[i].name;
        }
    }
    return NULL;
}

typedef struct {
    uint32_t id;
    af_attr_type_t type;
} id_type_map_t;

#define _AF_ATTR_ATTRDEF(_attr_id_num,_attr_id_name,_attr_type,_attr_get_timeout,_attr_owner,_attr_flags) \
    { .id = _attr_id_num, .type = _attr_type }

static id_type_map_t sIdTypeMap[] = {
    _AF_ATTR_ATTRIBUTES
};

af_attr_type_t vf_get_type_for_attribute(uint32_t attrId)
{
    for (int i=0; i < sizeof(sIdTypeMap)/sizeof(sIdTypeMap[0]); i++) {
        if (sIdTypeMap[i].id == attrId) {
            return sIdTypeMap[i].type;
        }
    }
    return AF_ATTR_TYPE_UNKNOWN;
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

uint8_t *vf_alloc_and_convert_input_value(af_attr_type_t type, const char *val, int *lengthP)
{
    uint8_t *setValue = NULL;

    if (lengthP == NULL) {
        return NULL;
    }

    switch (type) {
        case AF_ATTR_TYPE_SINT8:
        {
            int32_t long_val = strtol(val, NULL, 10);
            if ((long_val > INT8_MAX) || (long_val < INT8_MIN)) {
                fprintf(stderr, "value outside of int8_t range\n");
                AFLOG_ERR("vf_alloc_and_convert_input_val_int8:val=%s:value outside of int8_t range", val);
                return NULL;
            }
            setValue = (uint8_t *)malloc(sizeof(int8_t));
            if (setValue == NULL) {
                fprintf(stderr, "Memory allocation error\n");
                AFLOG_ERR("vf_alloc_and_convert_input_val_mem::can't allocate space for value");
                return NULL;
            }
            int8_t value = (int8_t)long_val;
            memcpy(setValue, &value, sizeof(value));
            *lengthP = sizeof(int8_t);
            break;
        }

        case AF_ATTR_TYPE_SINT16:
        {
            int32_t long_val = strtol(val, NULL, 10);
            if ((long_val > INT16_MAX) || (long_val < INT16_MIN)) {
                fprintf(stderr, "value outside of int16_t range\n");
                AFLOG_ERR("vf_alloc_and_convert_input_val_int16:val=%s:value outside of int16_t range", val);
                return NULL;
            }
            setValue = (uint8_t *)malloc(sizeof(int16_t));
            if (setValue == NULL) {
                fprintf(stderr, "Memory allocation error\n");
                AFLOG_ERR("vf_alloc_and_convert_input_val_mem::can't allocate space for value");
                return NULL;
            }
            af_attr_store_int16(setValue, (int16_t)long_val);
            *lengthP = sizeof(int16_t);
            break;
        }

        case AF_ATTR_TYPE_SINT32:
        {
            int32_t long_val = strtol(val, NULL, 10);
            if ((long_val == INT32_MIN || long_val == INT32_MAX) && errno == ERANGE) {
                fprintf(stderr, "value outside of int32_t range\n");
                AFLOG_ERR("vf_alloc_and_convert_input_val_int32:val=%s:value outside of int32_t range", val);
                return NULL;
            }
            setValue = (uint8_t *)malloc(sizeof(int32_t));
            if (setValue == NULL) {
                fprintf(stderr, "Memory allocation error\n");
                AFLOG_ERR("vf_alloc_and_convert_input_val_mem::can't allocate space for value");
                return NULL;
            }
            af_attr_store_int32(setValue, long_val);
            *lengthP = sizeof(int32_t);
            break;
        }

        case AF_ATTR_TYPE_UTF8S:
        {
            int size = strlen(val) + 1;
            setValue = (uint8_t *)malloc(size);
            if (setValue == NULL) {
                fprintf(stderr, "Memory allocation error\n");
                AFLOG_ERR("vf_alloc_and_convert_input_val_mem::can't allocate space for value");
                return NULL;
            }
            memcpy(setValue, val, size);
            *lengthP = size;
            break;
        }

        case AF_ATTR_TYPE_BYTES:
        {
            const char *tmp = val;
            int l = 0;
            while (*tmp != '\0') {
                l++;
                if (!isxdigit(*tmp)) {
                    fprintf(stderr, "illegal hex digit in param\n");
                    AFLOG_ERR("vf_alloc_and_convert_input_value_xdigit:val=%s", val);
                    return NULL;
                }
                tmp++;
            }

            if (l == 0) {
                /* NULL value case: allocate something we can free later */
                setValue = (uint8_t *)malloc(1);
                if (setValue == NULL) {
                    fprintf(stderr, "Memory allocation error\n");
                    AFLOG_ERR("vf_alloc_and_convert_input_val_mem0::can't allocate space for value");
                    return NULL;
                }
                *lengthP = 0;
                break;
            }

            if ((l % 2) != 0) {
                fprintf(stderr, "hex values must have an even number of digits in param\n");
                AFLOG_ERR("vf_alloc_and_convert_input_value_xlen:len=%d", l);
                return NULL;
            }

            int len = l/2;
            setValue = (uint8_t *)malloc(len);
            if (setValue == NULL) {
                fprintf(stderr, "Memory allocation error\n");
                AFLOG_ERR("vf_alloc_and_convert_input_val_mem::can't allocate space for value");
                return NULL;
            }

            for (l = 0; l < len; l++) {
                setValue[l] = hexnybble(val[l*2]) * 16 + hexnybble(val[l*2+1]);
            }
            *lengthP = len;
            break;
        }

        default:
            fprintf(stderr, "Illegal type");
            AFLOG_ERR("vf_alloc_and_convert_input_val_mem:argType=%d:illegal type", type);
            return NULL;
            break;
    }

    return setValue;
}

char *vf_alloc_and_convert_output_value(af_attr_type_t argType, uint8_t *value, int length)
{
    char *output = NULL;

    switch (argType) {
        case AF_ATTR_TYPE_UTF8S:
            output = (char *)malloc(length + 1);
            if (output != NULL) {
                memcpy(output, value, length);
                output[length] = '\0';
            }
            break;
        case AF_ATTR_TYPE_SINT8:
            output = (char *)malloc(5); /* maximum size of decimal int8 + null terminator */
            if (output != NULL) {
                sprintf (output, "%d", *(int8_t *)value);
            }
            break;
        case AF_ATTR_TYPE_SINT16:
            output = (char *)malloc(7); /* maximum size of decimal int16 + null terminator */
            if (output != NULL) {
                sprintf (output, "%d", af_attr_get_int16(value));
            }
            break;
        case AF_ATTR_TYPE_SINT32:
            output = (char *)malloc(12); /* maximum size of decimal int32 + null terminator */
            if (output != NULL) {
                sprintf (output, "%d", af_attr_get_int32(value));
            }
            break;
        case AF_ATTR_TYPE_BYTES:
            output = (char *)malloc(length * 2 + 1); /* number of nybbles + null terminator */
            if (output != NULL) {
                output[0] = '\0'; /* in case the length is zero */
                for (int i = 0; i<length; i++) {
                    sprintf (output + (i * 2), "%02x", *((uint8_t *)value+i));
                }
            }
            break;
        default:
            AFLOG_ERR("vf_alloc_and_convert_output_value_format:value_format=%d", argType);
            break;
    }

    return output;
}

char *vf_alloc_and_convert_output_value_for_execv(af_attr_type_t argType, uint8_t *value, int length)
{
    if (argType == AF_ATTR_TYPE_UTF8S) {
        char *output = NULL;
        int nb = 0;
        char *c = (char *)value;
        while (*c) {
            if (*c == '\'') {
                nb += 4;
            } else {
                nb++;
            }
            c++;
        }
        output = (char *)malloc(nb + 2 + 1); /* include space for escaped chars, quotes, term */
        if (output != NULL) {
            char *ci = (char *)value;
            char *co = (char *)output;
            *co++ = '\'';
            while (*ci) {
                if (*ci == '\'') {
                    *co++ = '\'';
                    *co++ = '\\';
                    *co++ = '\'';
                }
                *co++ = *ci++;
            }
            *co++ = '\'';
            *co = '\0';
        }
        return output;
    } else {
        return vf_alloc_and_convert_output_value(argType, value, length);
    }
}
