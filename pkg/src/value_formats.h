/*
 * file value_formats.h -- definitions for value formats
 *
 * Copyright (c) 2016-2018 Afero, Inc. All rights reserved.
 *
 */

#include <stdint.h>

#define VALUE_FORMATS \
    _VF_DEFN(-,UNKNOWN), \
    _VF_DEFN(u8,UINT8), \
    _VF_DEFN(i8,INT8), \
    _VF_DEFN(u16,UINT16), \
    _VF_DEFN(i16,INT16), \
    _VF_DEFN(u32,UINT32), \
    _VF_DEFN(i32,INT32), \
    _VF_DEFN(h,HEX), \
    _VF_DEFN(s,STRING) ,\

#define _VF_DEFN(_x,_y) VALUE_FORMAT_##_y
typedef enum {
    VALUE_FORMATS
    NUM_VALUE_FORMATS
} value_format_t;
#undef _VF_DEFN


value_format_t vf_get_format_for_name(const char *formatString);
char *vf_get_name_for_format(value_format_t vf);
uint8_t *vf_alloc_and_convert_input_value(value_format_t type, const char *val, int *lengthP);
char *vf_alloc_and_convert_output_value(value_format_t type, uint8_t *val, int length);
