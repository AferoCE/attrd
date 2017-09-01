/*
 * attrd_attr.c -- attribute daemon attribute implementation
 *
 * Copyright (c) 2017 Afero, Inc. All rights reserved.
 *
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
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

#define REBOOT_REASON_FILE_PATH "/afero_nv/reboot_reason"

static void handle_reboot_reason_get_request(uint32_t seqNum, uint16_t getId)
{
    /* check if the reboot reason file exists */
    struct stat st;
    if (stat(REBOOT_REASON_FILE_PATH, &st) < 0) {
        if (errno == ENOENT) {
            send_attrd_get_response(AF_ATTR_STATUS_OK, seqNum, getId, (uint8_t *)"", 1);
        } else {
            AFLOG_ERR("attrd_reboot_reason_stat:errno=%d", errno);
        }

        return;
    }

    /* capture the reboot reason file modification time */
    time_t utc = st.st_mtime;
    /* ctime uses a shared buffer. I don't like it so I copy it away immediately */
    char dateBuf[32];
    strcpy(dateBuf, ctime(&utc)); /* format is "Www Mmm Dd hh:mm:ss yyyy\n" : 25 chars + nul char */
    /* chop off the \n from the date buffer */
    int nc = strlen(dateBuf);
    if (nc > 0) {
        dateBuf[nc - 1] = '\0';
    }

    char contents[100];

    int fd = open(REBOOT_REASON_FILE_PATH, O_RDONLY);
    if (fd < 0) {
        AFLOG_ERR("attrd_reboot_reason_open:errno=%d", errno);
        return;
    }

    nc = read(fd, contents, sizeof(contents) - 1);
    close(fd);

    if (nc < 0) {
        AFLOG_ERR("attrd_reboot_reason_read:errno=%d", errno);
        return;
    }
    contents[nc] = '\0';

    char reason[100];
    nc = snprintf(reason, sizeof(reason), "%s:%s", dateBuf, contents);

    send_attrd_get_response(AF_ATTR_STATUS_OK, seqNum, getId, (uint8_t *)reason, nc);
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
        case AF_ATTR_ATTRD_REBOOT_REASON :
            handle_reboot_reason_get_request(seqNum, getId);
            break;

        default :
            break;
    }
}
