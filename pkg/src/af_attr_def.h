/*
 * file af_attr_def.h -- definitions for attribute daemon
 *
 * Copyright (c) 2016 Afero, Inc. All rights reserved.
 *
 */
#ifndef __AF_ATTR_DEF_H__
#define __AF_ATTR_DEF_H__

#define ATTR_NAME_SIZE 64
#define ATTR_OWNER_NAME_SIZE 32

/*
 * The owner ID in the enum will have AF_ATTR_OWNER_ prepended.
 * For example, the attribute daemon owner id is AF_ATTR_OWNER_ATTRD
 */

#define _OWNERS \
    _OWNERDEF(UNKNOWN),  \
    _OWNERDEF(ATTRD),    \
    _OWNERDEF(ATTRTEST), \
    _OWNERDEF(FSD),      \
    _OWNERDEF(WAN),      \
    _OWNERDEF(CONNMGR),  \
    _OWNERDEF(WIFISTAD), \
    _OWNERDEF(HUBBY),    \

#define AF_ATTR_FLAG_WRITABLE (1<<0)
#define AF_ATTR_FLAG_NOTIFY   (1<<1)

/*
 * The attribute ID in the enum will have AF_ATTR_ and the owner prepended.
 * For example the Wi-Fi secret attribute ID will be AF_ATTR_WIFISTA_SECRET
 */

#define _ATTRIBUTES \
    _ATTRDEF(1100,  SCRATCHWO,          0,  5, ATTRTEST,   AF_ATTR_FLAG_WRITABLE | AF_ATTR_FLAG_NOTIFY), \
    _ATTRDEF(1101,  SCRATCHRO,          0,  5, ATTRTEST,   0), \
    _ATTRDEF(51600, REPORT_RSSI_CHANGES,0,  5, ATTRD,      AF_ATTR_FLAG_WRITABLE | AF_ATTR_FLAG_NOTIFY), \
    _ATTRDEF(51601, RSRP,               0,  5, WAN,        AF_ATTR_FLAG_NOTIFY), \
    _ATTRDEF(51602, BARS,               0,  5, WAN,        AF_ATTR_FLAG_NOTIFY), \
    _ATTRDEF(51603, POWER_INFO,         0,  5, WAN,        0), \
    _ATTRDEF(51604, CAMP_INFO,          0,  5, WAN,        0), \
    _ATTRDEF(51605, SERVING_INFO,       0,  5, WAN,        0), \
    _ATTRDEF(51606, NEIGHBOR_INFO,      0,  5, WAN,        0), \
    _ATTRDEF(51607, FREESCALE_VERSION,  0,  5, FSD,        AF_ATTR_FLAG_NOTIFY), \
    _ATTRDEF(51608, AP_LIST,            0, 20, WIFISTAD,   AF_ATTR_FLAG_NOTIFY), \
    _ATTRDEF(51609, CREDS,              0,  5, WIFISTAD,   AF_ATTR_FLAG_WRITABLE | AF_ATTR_FLAG_NOTIFY), \
    _ATTRDEF(51610, AVAILABLE,          0,  5, WAN,        AF_ATTR_FLAG_NOTIFY), \
    _ATTRDEF(51611, STATE,              0,  5, HUBBY,      AF_ATTR_FLAG_NOTIFY), \
    _ATTRDEF(51612, OTA_UPGRADE_PATH,   0,  5, HUBBY,      AF_ATTR_FLAG_NOTIFY), \
    _ATTRDEF(51613, DEBUG_LEVEL,        0,  5, ATTRD,      AF_ATTR_FLAG_WRITABLE), \
    _ATTRDEF(51614, DEBUG_LEVEL,        0,  5, WIFISTAD,   AF_ATTR_FLAG_WRITABLE), \
    _ATTRDEF(51615, DEBUG_LEVEL,        0,  5, WAN,        AF_ATTR_FLAG_WRITABLE), \
    _ATTRDEF(51616, DEBUG_LEVEL,        0,  5, CONNMGR,    AF_ATTR_FLAG_WRITABLE), \
    _ATTRDEF(65004, CONFIGURED_SSID,    0,  5, WIFISTAD,   AF_ATTR_FLAG_NOTIFY), \
    _ATTRDEF(65005, WIFI_RSSI,          0,  5, WIFISTAD,   AF_ATTR_FLAG_NOTIFY), \
    _ATTRDEF(65006, WIFI_STEADY_STATE,  0,  5, WIFISTAD,   AF_ATTR_FLAG_WRITABLE | AF_ATTR_FLAG_NOTIFY), \
    _ATTRDEF(65007, WIFI_SETUP_STATE,   0,  5, WIFISTAD,   AF_ATTR_FLAG_WRITABLE | AF_ATTR_FLAG_NOTIFY), \
    _ATTRDEF(65008, NETWORK_TYPE,       0,  5, CONNMGR,    AF_ATTR_FLAG_NOTIFY), \

#define _ATTRDEF(_attr_id_num,_attr_id_name,_attr_type,_attr_get_timeout,_attr_owner,_attr_flags) AF_ATTR_##_attr_owner##_##_attr_id_name=_attr_id_num

typedef enum {
     _ATTRIBUTES
} attribute_id_t;

#undef _ATTRDEF

#define _OWNERDEF(_owner) AF_ATTR_OWNER_##_owner

typedef enum {
    _OWNERS
} attribute_owner_t;

#undef _OWNERDEF

#endif // __AF_ATTR_DEF_H__
