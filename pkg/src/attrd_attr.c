/*
 * attrd_attr.c -- attribute daemon attribute implementation
 *
 * Copyright (c) 2017 Afero, Inc. All rights reserved.
 *
 */
#include <event2/event.h>
#include "af_log.h"
#include "af_attr_client.h"
#include "attrd_attr.h"

static int8_t sReportRssiChanges = 0;

int handle_attrd_set_request(uint32_t attrId, uint8_t *data, int size)
{
    int retVal = AF_ATTR_STATUS_NOT_IMPLEMENTED;

    switch (attrId) {
        case AF_ATTR_ATTRD_DEBUG_LEVEL :
        {
            int8_t level = *(int8_t *)data;
            if (level < 0) {
                level = 0;
            }
            g_debugLevel = level;
            AFLOG_INFO("attrd_debug_level_set:level=%d", level);
            retVal = AF_ATTR_STATUS_OK;
            break;
        }
        case AF_ATTR_ATTRD_REPORT_RSSI_CHANGES :
        {
            int8_t reportChanges = *(int8_t *)data;
            sReportRssiChanges = (reportChanges != 0);
            AFLOG_INFO("attrd_report_rssi_changes_set:reportChanges=%d", sReportRssiChanges);
            retVal = AF_ATTR_STATUS_OK;
            break;
        }
        default :
            break;
    }
    return retVal;
}

void handle_attrd_get_request(uint32_t seqNum, uint16_t getId, uint32_t attrId)
{
    switch (attrId) {
        case AF_ATTR_ATTRD_DEBUG_LEVEL :
        {
            int8_t level = g_debugLevel;
            AFLOG_INFO("attrd_debug_level_get:level=%d", level);
            send_attrd_get_response(AF_ATTR_STATUS_OK, seqNum, getId, (uint8_t *)&level, sizeof(level));
            break;
        }
        case AF_ATTR_ATTRD_REPORT_RSSI_CHANGES :
            AFLOG_INFO("attrd_report_rssi_changes_get:reportChanges=%d", sReportRssiChanges);
            send_attrd_get_response(AF_ATTR_STATUS_OK, seqNum, getId, (uint8_t *)&sReportRssiChanges, sizeof(sReportRssiChanges));
            break;
        case AF_ATTR_ATTRD_SYSTEM_TIME :
        {
            struct timeval tv;
            uint8_t buf[sizeof(tv.tv_sec)];
            gettimeofday(&tv, NULL);
            AFLOG_INFO("attrd_system_time_get:time=%d", (int)tv.tv_sec);
            af_attr_store_int32(buf, tv.tv_sec);
            send_attrd_get_response(AF_ATTR_STATUS_OK, seqNum, getId, buf, sizeof(tv.tv_sec));
            break;
        }
        default :
            break;
    }
}
