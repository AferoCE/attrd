/*
 * attrd_attr.h -- attribute daemon attribute definitions
 *
 * Copyright (c) 2017 Afero, Inc. All rights reserved.
 *
 */

/* attrd.c provides this function */
void send_attrd_get_response(uint8_t status, uint32_t seqNum, uint16_t getId, uint8_t *value, int size);

/* attrd_attr.c provides these function */
int handle_attrd_set_request(uint32_t attrId, uint8_t *data, int size);
void handle_attrd_get_request(uint32_t seqNum, uint16_t getId, uint32_t attrId);
