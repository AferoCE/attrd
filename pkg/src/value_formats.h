/*
 * file value_formats.h -- definitions for value formats
 *
 * Copyright (c) 2016-2018 Afero, Inc. All rights reserved.
 *
 */

#ifndef __VALUE_FORMATS_H__
#define __VALUE_FORMATS_H__

#include <stdint.h>
#include "af_attr_def.h"

uint8_t *vf_alloc_and_convert_input_value(af_attr_type_t type, const char *val, int *lengthP);
char *vf_alloc_and_convert_output_value(af_attr_type_t type, uint8_t *val, int length);
char *vf_alloc_and_convert_output_value_for_execv(af_attr_type_t type, uint8_t *value, int length);
af_attr_type_t vf_get_type_for_attribute(uint32_t attrId);
int vf_get_size_for_type(af_attr_type_t type);
char *vf_get_name_for_type(af_attr_type_t vf);

#endif // __VALUE_FORMATS_H__
