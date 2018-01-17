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

#define _VF_DEFN(_x,_y) #_x

static char *s_valueFormatNames[NUM_VALUE_FORMATS] = {
    VALUE_FORMATS
};

value_format_t vf_get_format_for_name(const char *formatString)
{
    int i;
    for (i = 0; i < NUM_VALUE_FORMATS; i++) {
        if (!strcmp(formatString, s_valueFormatNames[i])) {
            return i;
        }
    }
    return VALUE_FORMAT_UNKNOWN;
}

char *vf_get_name_for_format(value_format_t format)
{
    if (format < 0 || format >= NUM_VALUE_FORMATS) {
        return s_valueFormatNames[VALUE_FORMAT_UNKNOWN];
    } else {
        return s_valueFormatNames[format];
    }
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

uint8_t *vf_alloc_and_convert_input_value(value_format_t type, const char *val, int *lengthP)
{
    uint8_t *setValue = NULL;

    if (lengthP == NULL) {
        return NULL;
    }

    switch (type) {

        case VALUE_FORMAT_UINT8:
        {
            int32_t long_val = strtol(val, NULL, 10);
            if ((long_val > UINT8_MAX) || (long_val < 0)) {
                fprintf(stderr, "value outside of uint8_t range\n");
                AFLOG_ERR("vf_alloc_and_convert_input_val_uint8:val=%s:value outside of uint8_t range", val);
                return NULL;
            }
            uint8_t value = (uint8_t)long_val;
            setValue = (uint8_t *)malloc(sizeof(value));
            if (setValue == NULL)
            {
                fprintf(stderr, "Memory allocation error\n");
                AFLOG_ERR("vf_alloc_and_convert_input_val_mem::can't allocate space for value");
                return NULL;
            }
            memcpy(setValue, &value, (sizeof(value)));
            *lengthP = sizeof(uint8_t);
            break;
        }

        case VALUE_FORMAT_UINT16:
        {
            int32_t long_val = strtol(val, NULL, 10);
            if ((long_val > UINT16_MAX) || (long_val < 0)) {
                fprintf(stderr, "value outside of uint16_t range\n");
                AFLOG_ERR("vf_alloc_and_convert_input_val_uint16:val=%s:value outside of uint32_t range", val);
                return NULL;
            }
            setValue = (uint8_t *)malloc(sizeof(uint16_t));
            if (setValue == NULL)
            {
                fprintf(stderr, "Memory allocation error\n");
                AFLOG_ERR("vf_alloc_and_convert_input_val_mem::can't allocate space for value");
                return NULL;
            }
            af_attr_store_uint16(setValue, (uint16_t)long_val);
            *lengthP = sizeof(uint16_t);
            break;
        }

        case VALUE_FORMAT_UINT32:
        {
            errno = 0;
            uint32_t long_val = strtoul(val, NULL, 10);
            if (val[0] == '-' || (long_val == UINT32_MAX && errno == ERANGE)) {
                fprintf(stderr, "value outside of uint32_t range\n");
                AFLOG_ERR("vf_alloc_and_convert_input_val_uint32:val=%s:value outside of uint32_t range", val);
                return NULL;
            }
            setValue = (uint8_t *)malloc(sizeof(uint32_t));
            if (setValue == NULL) {
                fprintf(stderr, "Memory allocation error\n");
                AFLOG_ERR("vf_alloc_and_convert_input_val_mem::can't allocate space for value");
                return NULL;
            }
            af_attr_store_uint32(setValue, long_val);
            *lengthP = sizeof(uint32_t);
            break;
        }

        case VALUE_FORMAT_INT8:
        {
            int32_t long_val = strtol(val, NULL, 10);
            if ((long_val > INT8_MAX) || (long_val < INT8_MIN)) {
                fprintf(stderr, "value outside of int8_t range\n");
                AFLOG_ERR("vf_alloc_and_convert_input_val_int8:val=%s:value outside of int8_t range", val);
                return NULL;
            }
            setValue = (uint8_t *)malloc(sizeof(int8_t));
            if (setValue == NULL)
            {
                fprintf(stderr, "Memory allocation error\n");
                AFLOG_ERR("vf_alloc_and_convert_input_val_mem::can't allocate space for value");
                return NULL;
            }
            int8_t value = (int8_t)long_val;
            memcpy(setValue, &value, sizeof(value));
            *lengthP = sizeof(int8_t);
            break;
        }

        case VALUE_FORMAT_INT16:
        {
            int32_t long_val = strtol(val, NULL, 10);
            if ((long_val > INT16_MAX) || (long_val < INT16_MIN)) {
                fprintf(stderr, "value outside of int16_t range\n");
                AFLOG_ERR("vf_alloc_and_convert_input_val_int16:val=%s:value outside of int16_t range", val);
                return NULL;
            }
            setValue = (uint8_t *)malloc(sizeof(int16_t));
            if (setValue == NULL)
            {
                fprintf(stderr, "Memory allocation error\n");
                AFLOG_ERR("vf_alloc_and_convert_input_val_mem::can't allocate space for value");
                return NULL;
            }
            af_attr_store_int16(setValue, (int16_t)long_val);
            *lengthP = sizeof(int16_t);
            break;
        }

        case VALUE_FORMAT_INT32:
        {
            int32_t long_val = strtol(val, NULL, 10);
            if ((long_val == INT32_MIN || long_val == INT32_MAX) && errno == ERANGE) {
                fprintf(stderr, "value outside of int32_t range\n");
                AFLOG_ERR("vf_alloc_and_convert_input_val_int32:val=%s:value outside of int32_t range", val);
                return NULL;
            }
            setValue = (uint8_t *)malloc(sizeof(int32_t));
            if (setValue == NULL)
            {
                fprintf(stderr, "Memory allocation error\n");
                AFLOG_ERR("vf_alloc_and_convert_input_val_mem::can't allocate space for value");
                return NULL;
            }
            af_attr_store_int32(setValue, long_val);
            *lengthP = sizeof(int32_t);
            break;
        }

        case VALUE_FORMAT_STRING:
        {
            int size = strlen(val) + 1;
            setValue = (uint8_t *)malloc(size);
            if (setValue == NULL)
            {
                fprintf(stderr, "Memory allocation error\n");
                AFLOG_ERR("vf_alloc_and_convert_input_val_mem::can't allocate space for value");
                return NULL;
            }
            memcpy(setValue, val, size);
            *lengthP = size;
            break;
        }

        case VALUE_FORMAT_HEX:
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
            if (l == 0 || (l % 2) != 0)
            {
                fprintf(stderr, "hex values must have an even number of digits in param\n");
                AFLOG_ERR("vf_alloc_and_convert_input_value_xlen:len=%d", l);
                return NULL;
            }

            int len = l/2;
            setValue = (uint8_t *)malloc(len);
            if (setValue == NULL)
            {
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

char *vf_alloc_and_convert_output_value(value_format_t argType, uint8_t *value, int length)
{
    char *output = NULL;

    switch (argType) {
        case VALUE_FORMAT_STRING: {
            int i, nb = 0;
            for (i = 0; i < length; i++) {
                if (value[i] == '\"' || value[i] == '\\') {
                    nb++;
                }
            }
            output = (char *)malloc(length + nb + 2 + 1); /* include quotes and null terminator */
            if (output != NULL) {
                char *c = output;
                *c++ = '\"';
                for (i = 0; i < length && value[i] != '\0'; i++) {
                    if (value[i] == '\"' || value[i] == '\\') {
                        *c++ = '\\';
                    }
                    *c++ = value[i];
                }
                *c++ = '\"';
                *c = '\0';
            }
            break;
        }
        case VALUE_FORMAT_UINT8:
            output = (char *)malloc(4); /* maximum size of decimal uint8 + null terminator */
            if (output != NULL) {
                sprintf (output, "%u", *(uint8_t *)value);
            }
            break;
        case VALUE_FORMAT_UINT16:
            output = (char *)malloc(6); /* maximum size of decimal uint16 + null terminator */
            if (output != NULL) {
                sprintf (output, "%u", af_attr_get_uint16(value));
            }
            break;
        case VALUE_FORMAT_UINT32:
            output = (char *)malloc(11); /* maximum size of decimal uint32 + null terminator */
            if (output != NULL) {
                sprintf (output, "%u", af_attr_get_uint32(value));
            }
            break;
        case VALUE_FORMAT_INT8:
            output = (char *)malloc(5); /* maximum size of decimal int8 + null terminator */
            if (output != NULL) {
                sprintf (output, "%d", *(int8_t *)value);
            }
            break;
        case VALUE_FORMAT_INT16:
            output = (char *)malloc(7); /* maximum size of decimal int16 + null terminator */
            if (output != NULL) {
                sprintf (output, "%d", af_attr_get_int16(value));
            }
            break;
        case VALUE_FORMAT_INT32:
            output = (char *)malloc(12); /* maximum size of decimal int32 + null terminator */
            if (output != NULL) {
                sprintf (output, "%d", af_attr_get_int32(value));
            }
            break;
        case VALUE_FORMAT_HEX:
            output = (char *)malloc(length * 2 + 1); /* number of nybbles + null terminator */
            if (output != NULL) {
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
