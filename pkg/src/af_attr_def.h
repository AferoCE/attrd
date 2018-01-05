/*
 * file af_attr_def.h -- definitions for attribute daemon
 *
 * Copyright (c) 2016-2017 Afero, Inc. All rights reserved.
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
    _OWNERDEF(EDGED),    \
    _OWNERDEF(OTAMGR),   \

#define AF_ATTR_FLAG_WRITABLE (1<<0)
#define AF_ATTR_FLAG_NOTIFY   (1<<1)


/*
 * The attributes from 1 to 1023 are referred to as MCU Application Specific
 * attributes.  In attrd implementation, these attributes are owned by hubby.
 */
#define EDGE_ATTR_START   1
#define EDGE_ATTR_END     1023

#define EDGE_ATTR_GETTIMEOUT  5

#define EDGE_ATTR_OWNER_NAME_PREFIX     "HUBBY_EDGE_ATTR_"
#define EDGE_ATTR_OWNER_NAME_PREFIX_LEN  strlen(EDGE_ATTR_OWNER_NAME_PREFIX)


/*
 * The attribute ID in the enum will have AF_ATTR_ and the owner prepended.
 * For example the Wi-Fi secret attribute ID will be AF_ATTR_WIFISTA_SECRET
 */

#define _ATTRIBUTES \
    _ATTRDEF(1100,  SCRATCHWO,          0,  5, ATTRTEST,   AF_ATTR_FLAG_WRITABLE | AF_ATTR_FLAG_NOTIFY), \
    _ATTRDEF(1101,  SCRATCHRO,          0,  5, ATTRTEST,   0), \
    _ATTRDEF(51600, REPORT_RSSI_CHANGES,0,  5, ATTRD,      AF_ATTR_FLAG_WRITABLE | AF_ATTR_FLAG_NOTIFY), \
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
    _ATTRDEF(51617, DEBUG_LEVEL,        0,  5, EDGED,      AF_ATTR_FLAG_WRITABLE), \
    _ATTRDEF(51618, OTA_UPD_PATH_PREFIX,0,  5, OTAMGR,     0), \
    _ATTRDEF(51619, PROFILE_UPDATED,    0,  5, HUBBY,      0), \
    _ATTRDEF(51620, REVISION,           0,  5, CONNMGR,    AF_ATTR_FLAG_WRITABLE), \
    _ATTRDEF(51621, REVISION,           0,  5, WIFISTAD,   AF_ATTR_FLAG_WRITABLE), \
    _ATTRDEF(51622, REVISION,           0,  5, WAN,        AF_ATTR_FLAG_WRITABLE), \
    _ATTRDEF(51623, REVISION,           0,  5, ATTRD,      AF_ATTR_FLAG_WRITABLE), \
    _ATTRDEF(60002, CONCLAVE_ACCESS,    0,  5, HUBBY,      AF_ATTR_FLAG_NOTIFY ), \
    _ATTRDEF(65001, UTC_OFFSET_DATA,    0,  5, ATTRD,      AF_ATTR_FLAG_WRITABLE | AF_ATTR_FLAG_NOTIFY ), \
    _ATTRDEF(65002, MAX_RELINK_INTERVAL,0,  5, HUBBY,      AF_ATTR_FLAG_WRITABLE | AF_ATTR_FLAG_NOTIFY ), \
    _ATTRDEF(65003, ATTRIBUTE_CRC32,    0,  5, HUBBY,      AF_ATTR_FLAG_WRITABLE | AF_ATTR_FLAG_NOTIFY ), \
    _ATTRDEF(65004, CONFIGURED_SSID,    0,  5, WIFISTAD,   AF_ATTR_FLAG_NOTIFY), \
    _ATTRDEF(65005, WIFI_RSSI,          0,  5, WIFISTAD,   AF_ATTR_FLAG_NOTIFY), \
    _ATTRDEF(65006, WIFI_STEADY_STATE,  0,  5, WIFISTAD,   AF_ATTR_FLAG_WRITABLE | AF_ATTR_FLAG_NOTIFY), \
    _ATTRDEF(65007, WIFI_SETUP_STATE,   0,  5, WIFISTAD,   AF_ATTR_FLAG_WRITABLE | AF_ATTR_FLAG_NOTIFY), \
    _ATTRDEF(65008, NETWORK_TYPE,       0,  5, CONNMGR,    AF_ATTR_FLAG_NOTIFY), \
    _ATTRDEF(65012, COMMAND,            0,  5, HUBBY,      AF_ATTR_FLAG_NOTIFY), \
    _ATTRDEF(65013, ASR_STATE,          0,  5, HUBBY,      AF_ATTR_FLAG_WRITABLE ), \
    _ATTRDEF(65015, LINKED_TIMESTAMP,   0,  5, HUBBY,      AF_ATTR_FLAG_NOTIFY ), \
    _ATTRDEF(65019, REBOOT_REASON,      0,  5, ATTRD,      AF_ATTR_FLAG_NOTIFY), \
    _ATTRDEF(65020, BLE_COMMS,          0,  5, HUBBY,      AF_ATTR_FLAG_NOTIFY), \
    _ATTRDEF(65022, NET_CAPABILITIES,   0,  5, CONNMGR,    AF_ATTR_FLAG_NOTIFY), \
    _ATTRDEF(65023, WIFI_CONTROL,       0,  5, WIFISTAD,   AF_ATTR_FLAG_WRITABLE | AF_ATTR_FLAG_NOTIFY), \
    _ATTRDEF(65024, WIFI_ITF_STATE,     0,  5, CONNMGR,    0), \
    _ATTRDEF(65025, WIFI_IPADDR,        0,  5, CONNMGR,    0), \
    _ATTRDEF(65026, WIFI_UPTIME,        0,  5, CONNMGR,    0), \
    _ATTRDEF(65027, WIFI_DL_DATA_USAGE, 0,  5, CONNMGR,    0), \
    _ATTRDEF(65028, WIFI_UL_DATA_USAGE, 0,  5, CONNMGR,    0), \
    _ATTRDEF(65029, WIFI_MAC_ADDR,      0,  5, CONNMGR,    0), \
    _ATTRDEF(65030, WIFI_KEY_MGMT,      0,  5, WIFISTAD,   0), \
    _ATTRDEF(65031, WIFI_GROUP_CIPHER,  0,  5, WIFISTAD,   0), \
    _ATTRDEF(65032, WIFI_PAIRWISE_CIPHER,0, 5, WIFISTAD,   0), \
    _ATTRDEF(65033, WIFI_HIDDEN_SSID,   0,  5, WIFISTAD,   0), \
    _ATTRDEF(65034, WAN_RSRP,           0,  5, WAN,        AF_ATTR_FLAG_NOTIFY), \
    _ATTRDEF(65035, WAN_BARS,           0,  5, WAN,        AF_ATTR_FLAG_NOTIFY), \
    _ATTRDEF(65036, WAN_CONTROL,        0,  5, WAN,        AF_ATTR_FLAG_WRITABLE | AF_ATTR_FLAG_NOTIFY), \
    _ATTRDEF(65037, WAN_ITF_STATE,      0,  5, WAN,        0), \
    _ATTRDEF(65038, WAN_IPADDR,         0,  5, CONNMGR,    0), \
    _ATTRDEF(65039, WAN_UPTIME,         0,  5, CONNMGR,    0), \
    _ATTRDEF(65040, WAN_DL_DATA_USAGE,  0,  5, CONNMGR,    0), \
    _ATTRDEF(65041, WAN_UL_DATA_USAGE,  0,  5, CONNMGR,    0), \
    _ATTRDEF(65042, WAN_IMEISV,         0,  5, WAN,        0), \
    _ATTRDEF(65043, WAN_IMSI,           0,  5, WAN,        0), \
    _ATTRDEF(65044, WAN_ICCID,          0,  5, WAN,        0), \
    _ATTRDEF(65045, WAN_RAT,            0,  5, WAN,        0), \
    _ATTRDEF(65046, WAN_REG_STATE,      0,  5, WAN,        0), \
    _ATTRDEF(65047, WAN_PS_STATE,       0,  5, WAN,        0), \
    _ATTRDEF(65048, WAN_MCC,            0,  5, WAN,        0), \
    _ATTRDEF(65049, WAN_MNC,            0,  5, WAN,        0), \
    _ATTRDEF(65050, WAN_LAC,            0,  5, WAN,        0), \
    _ATTRDEF(65051, WAN_CELL_ID,        0,  5, WAN,        0), \
    _ATTRDEF(65052, WAN_ROAMING_STATE,  0,  5, WAN,        0), \
    _ATTRDEF(65053, WAN_PLMN,           0,  5, WAN,        0), \
    _ATTRDEF(65054, WAN_APN,            0,  5, WAN,        0), \
    _ATTRDEF(65055, WAN_SIM_STATUS,     0,  5, WAN,        0), \
    _ATTRDEF(65056, WAN_DL_BIT_RATE,    0,  5, WAN,        0), \
    _ATTRDEF(65057, WAN_UL_BIT_RATE,    0,  5, WAN,        0), \
    _ATTRDEF(65058, ETH_CONTROL,        0,  5, CONNMGR,    AF_ATTR_FLAG_WRITABLE | AF_ATTR_FLAG_NOTIFY), \
    _ATTRDEF(65059, ETH_ITF_STATE,      0,  5, CONNMGR,    0), \
    _ATTRDEF(65060, ETH_IPADDR,         0,  5, CONNMGR,    0), \
    _ATTRDEF(65061, ETH_UPTIME,         0,  5, CONNMGR,    0), \
    _ATTRDEF(65062, ETH_DL_DATA_USAGE,  0,  5, CONNMGR,    0), \
    _ATTRDEF(65063, ETH_UL_DATA_USAGE,  0,  5, CONNMGR,    0), \
    _ATTRDEF(65064, ETH_MAC_ADDR,       0,  5, CONNMGR,    0), \
    _ATTRDEF(65065, SYSTEM_TIME,        0,  5, ATTRD,      0), \

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
