/*
 * attr_test.c -- attribute daemon client API test
 *
 * Copyright (c) 2016 Afero, Inc. All rights reserved.
 *
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <event2/event.h>
#include <event2/thread.h>

#include "af_log.h"
#include "af_attr_client.h"

struct event_base *sEventBase = NULL;

uint32_t g_debugLevel = 3;
static int sDoSet = 0;
static int sDoGet = 0;
static int sDoWait = 0;
static int sDoDaemon = 0;

static char *sSetString = NULL;


static void on_owner_set(uint32_t attributeId, uint16_t setId, uint8_t *value, int length, void *context)
{
    int status = AF_ATTR_STATUS_OK;
    printf("attribute set: attributeId=%d value=\"%s\"\n", attributeId, (char *)value);
    if (strcmp((char *)value, "reject") == 0) {
        status = AF_ATTR_STATUS_SET_REJECT_BUSY;
    }
    if (strcmp((char *)value, "quit") == 0) {
        event_base_loopbreak(sEventBase);
    }
    af_attr_send_set_response(status, setId);
}

static void on_get_request(uint32_t attributeId, uint16_t getId, void *context)
{
    if (attributeId == AF_ATTR_ATTRTEST_SCRATCHRO) {
        char reply[] = "This is the string that gets reported back when you get the SCRATCHRO attribute on the attribute test app.";
        af_attr_send_get_response(AF_ATTR_STATUS_OK, getId, (uint8_t *)reply, sizeof(reply));
    } else {
        af_attr_send_get_response(AF_ATTR_STATUS_ATTR_ID_NOT_FOUND, getId, NULL, 0);
    }
}

static void on_set_finished(int status, uint32_t attributeId, void *context)
{
    if (status != AF_ATTR_STATUS_OK) {
        printf("status=%d\n", status);
    }
    event_base_loopbreak(sEventBase);
}

static void on_notify(uint32_t attributeId, uint8_t *value, int length, void *context)
{
    printf("attribute notify: attributeId=%d value=\"%s\"\n", attributeId, (char *)value);
    event_base_loopbreak(sEventBase);
}

static void on_get_response(int status, uint32_t attributeId, uint8_t *value, int length, void *context)
{
    if (status != AF_ATTR_STATUS_OK) {
        printf ("status=%d\n", status);
    } else {
        printf ("attribute get: attributeId=%d value=\"%s\"\n", attributeId, (char *)value);
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
        status = af_attr_get (AF_ATTR_ATTRTEST_SCRATCHRO, on_get_response, NULL);
        if (status != AF_ATTR_STATUS_OK) {
            AFLOG_ERR("on_open_attr_get:status=%d", status);
        }
    }

    if (sDoSet && sSetString != NULL) {
        status = af_attr_set (AF_ATTR_ATTRTEST_SCRATCHWO, (uint8_t *)sSetString, strlen(sSetString) + 1, on_set_finished, NULL);
        if (status != AF_ATTR_STATUS_OK) {
            AFLOG_ERR("on_open_attr_set:status=%d", status);
        }
    }
}

void usage(char *name)
{
    printf ("%s -g | -s <value> | -w | -d\n", name);
}

int main(int argc, char *argv[])
{
    int opt;

    openlog("attr_test", LOG_PID, LOG_USER);

    while ((opt = getopt(argc, argv, "gs:wd")) != -1) {
        switch (opt) {
            case 'g' :
                sDoGet = 1;
                break;
            case 's' :
                sDoSet = 1;
                sSetString = optarg;
                break;
            case 'w' :
                sDoWait = 1;
                break;
            case 'd' :
                sDoDaemon = 1;
                break;
            default :
                break;
        }
    }

    /* make sure we selected one and only one option */
    if (sDoGet + sDoSet + sDoWait + sDoDaemon != 1) {
        usage(argv[0]);
        exit(1);
    }

    /* enable pthreads */
    evthread_use_pthreads();

    /* get an event_base */
    sEventBase = event_base_new();
    if (sEventBase == NULL) {
        AFLOG_ERR("attrd:event_base_new::can't allocate event base");
        return(1);
    }

    af_attr_range_t r = { AF_ATTR_ATTRTEST_SCRATCHWO, AF_ATTR_ATTRTEST_SCRATCHWO };

    int err = af_attr_open(sEventBase, (sDoDaemon ? "IPC.ATTRTEST" : "IPC.ATTRTESTC"),
                           (sDoWait ? 1 : 0), &r,
                           (sDoWait ? on_notify : NULL),        // notify callback
                           (sDoDaemon ? on_owner_set : NULL),   // owner set callback
                           (sDoDaemon ? on_get_request : NULL), // owner get callback
                           NULL,                                // close callback
                           on_open,                             // open callback
                           NULL);                               // context

    if (err != AF_ATTR_STATUS_OK) {
        AFLOG_ERR("wan_ipc_init_open:err=%d", err);
        return -1;
    }

    event_base_dispatch(sEventBase);

    af_attr_close();

    event_base_free(sEventBase);

    closelog();

    return 0;
}

