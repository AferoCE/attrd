/*
 * af_attr_def.h -- definitions for attribute daemon
 *
 * Copyright (c) 2016-2018 Afero, Inc. All rights reserved.
 *
 */
#ifndef __AF_ATTR_DEF_H__
#define __AF_ATTR_DEF_H__

#define AF_ATTR_NAME_SIZE 64
#define AF_ATTR_OWNER_NAME_SIZE 32

/*
 * The owner ID in the enum will have AF_ATTR_OWNER_ prepended.
 * For example, the attribute daemon owner id is AF_ATTR_OWNER_ATTRD
 */

#define _AF_ATTR_OWNERS \
    _AF_ATTR_OWNERDEF(UNKNOWN),  \
    _AF_ATTR_OWNERDEF(ATTRD),    \
    _AF_ATTR_OWNERDEF(ATTRTEST), \
    _AF_ATTR_OWNERDEF(FSD),      \
    _AF_ATTR_OWNERDEF(WAN),      \
    _AF_ATTR_OWNERDEF(CONNMGR),  \
    _AF_ATTR_OWNERDEF(WIFISTAD), \
    _AF_ATTR_OWNERDEF(HUBBY),    \
    _AF_ATTR_OWNERDEF(EDGED),    \
    _AF_ATTR_OWNERDEF(OTAMGR),   \
    _AF_ATTR_OWNERDEF(ATTRC),    \

#define _AF_ATTR_TYPES \
    _AF_ATTR_TYPE_DEFN(0,UNKNOWN,-1), \
    _AF_ATTR_TYPE_DEFN(1,BOOLEAN,1), \
    _AF_ATTR_TYPE_DEFN(2,SINT8,1),   \
    _AF_ATTR_TYPE_DEFN(3,SINT16,2),  \
    _AF_ATTR_TYPE_DEFN(4,SINT32,4),  \
    _AF_ATTR_TYPE_DEFN(5,SINT64,8),  \
    _AF_ATTR_TYPE_DEFN(6,FIXED_16_16,4), \
    _AF_ATTR_TYPE_DEFN(7,FIXED_32_32,8), \
    _AF_ATTR_TYPE_DEFN(21,BYTES,0),  \
    _AF_ATTR_TYPE_DEFN(20,UTF8S,0),  \

#define _AF_ATTR_TYPE_DEFN(_num,_name,_size) AF_ATTR_TYPE_##_name = _num

typedef enum {
    _AF_ATTR_TYPES
} af_attr_type_t;

#undef _AF_ATTR_TYPE_DEFN

#define AF_ATTR_FLAG_WRITABLE (1<<0)
#define AF_ATTR_FLAG_NOTIFY   (1<<1)
#define AF_ATTR_FLAG_MCU_HIDE (1<<2)


/*
 * The attributes from 1 to 1023 are referred to as MCU Application Specific
 * attributes.  In attrd implementation, these attributes are owned by hubby.
 */
#define AF_ATTR_EDGE_START   1
#define AF_ATTR_EDGE_END     1023

#define AF_ATTR_EDGE_GET_TIMEOUT (5)
/*
 * The attribute ID in the enum will have AF_ATTR_ and the owner prepended.
 * For example the Wi-Fi secret attribute ID will be AF_ATTR_WIFISTA_SECRET
 */

#define _AF_ATTR_ATTRIBUTES \
    _AF_ATTR_ATTRDEF(1100,  SCRATCHWO,            AF_ATTR_TYPE_UTF8S,  5, ATTRTEST,   AF_ATTR_FLAG_WRITABLE | AF_ATTR_FLAG_NOTIFY), \
    _AF_ATTR_ATTRDEF(1101,  SCRATCHRO,            AF_ATTR_TYPE_UTF8S,  5, ATTRTEST,   0), \
    _AF_ATTR_ATTRDEF(1102,  SCRATCHWO_BLOB,       AF_ATTR_TYPE_BYTES,  5, ATTRTEST,   AF_ATTR_FLAG_WRITABLE | AF_ATTR_FLAG_NOTIFY), \
    _AF_ATTR_ATTRDEF(1303,  MEDIA_UPLOAD_REQ,     AF_ATTR_TYPE_UTF8S,  5, HUBBY,      AF_ATTR_FLAG_WRITABLE), \
    _AF_ATTR_ATTRDEF(1304,  MEDIA_UPLOAD_RESP,    AF_ATTR_TYPE_UTF8S,  5, HUBBY,      AF_ATTR_FLAG_NOTIFY), \
    _AF_ATTR_ATTRDEF(51600, REPORT_RSSI_CHANGES,  AF_ATTR_TYPE_SINT8,  5, ATTRD,      AF_ATTR_FLAG_WRITABLE | AF_ATTR_FLAG_NOTIFY), \
    _AF_ATTR_ATTRDEF(51603, POWER_INFO,           AF_ATTR_TYPE_UTF8S,  5, WAN,        AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(51604, CAMP_INFO,            AF_ATTR_TYPE_UTF8S,  5, WAN,        AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(51605, SERVING_INFO,         AF_ATTR_TYPE_UTF8S,  5, WAN,        AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(51606, NEIGHBOR_INFO,        AF_ATTR_TYPE_UTF8S,  5, WAN,        AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(51607, FREESCALE_VERSION,    AF_ATTR_TYPE_SINT64, 5, FSD,        AF_ATTR_FLAG_NOTIFY), \
    _AF_ATTR_ATTRDEF(51608, AP_LIST,              AF_ATTR_TYPE_BYTES, 20, WIFISTAD,   AF_ATTR_FLAG_NOTIFY), \
    _AF_ATTR_ATTRDEF(51609, CREDS,                AF_ATTR_TYPE_BYTES,  5, WIFISTAD,   AF_ATTR_FLAG_WRITABLE | AF_ATTR_FLAG_NOTIFY), \
    _AF_ATTR_ATTRDEF(51610, AVAILABLE,            AF_ATTR_TYPE_SINT8,  5, WAN,        AF_ATTR_FLAG_NOTIFY), \
    _AF_ATTR_ATTRDEF(51611, STATE,                AF_ATTR_TYPE_SINT8,  5, HUBBY,      AF_ATTR_FLAG_NOTIFY), \
    _AF_ATTR_ATTRDEF(51612, OTA_UPGRADE_PATH,     AF_ATTR_TYPE_UTF8S,  5, HUBBY,      AF_ATTR_FLAG_NOTIFY), \
    _AF_ATTR_ATTRDEF(51613, DEBUG_LEVEL,          AF_ATTR_TYPE_SINT8,  5, ATTRD,      AF_ATTR_FLAG_WRITABLE), \
    _AF_ATTR_ATTRDEF(51614, DEBUG_LEVEL,          AF_ATTR_TYPE_SINT8,  5, WIFISTAD,   AF_ATTR_FLAG_WRITABLE), \
    _AF_ATTR_ATTRDEF(51615, DEBUG_LEVEL,          AF_ATTR_TYPE_SINT8,  5, WAN,        AF_ATTR_FLAG_WRITABLE), \
    _AF_ATTR_ATTRDEF(51616, DEBUG_LEVEL,          AF_ATTR_TYPE_SINT8,  5, CONNMGR,    AF_ATTR_FLAG_WRITABLE), \
    _AF_ATTR_ATTRDEF(51617, DEBUG_LEVEL,          AF_ATTR_TYPE_SINT8,  5, EDGED,      AF_ATTR_FLAG_WRITABLE), \
    _AF_ATTR_ATTRDEF(51618, OTA_UPD_PATH_PREFIX,  AF_ATTR_TYPE_UTF8S,  5, OTAMGR,     AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(51619, PROFILE_UPDATED,      AF_ATTR_TYPE_SINT8,  5, HUBBY,      AF_ATTR_FLAG_NOTIFY), \
    _AF_ATTR_ATTRDEF(51620, REVISION,             AF_ATTR_TYPE_UTF8S,  5, CONNMGR,    0), \
    _AF_ATTR_ATTRDEF(51621, REVISION,             AF_ATTR_TYPE_UTF8S,  5, WIFISTAD,   0), \
    _AF_ATTR_ATTRDEF(51622, REVISION,             AF_ATTR_TYPE_UTF8S,  5, WAN,        0), \
    _AF_ATTR_ATTRDEF(51623, REVISION,             AF_ATTR_TYPE_UTF8S,  5, ATTRD,      0), \
    _AF_ATTR_ATTRDEF(51624, MESSAGES_PASSED,      AF_ATTR_TYPE_SINT32, 5, HUBBY,      AF_ATTR_FLAG_NOTIFY | AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65004, CONFIGURED_SSID,      AF_ATTR_TYPE_UTF8S,  5, WIFISTAD,   AF_ATTR_FLAG_NOTIFY), \
    _AF_ATTR_ATTRDEF(65005, WIFI_RSSI,            AF_ATTR_TYPE_SINT8,  5, WIFISTAD,   AF_ATTR_FLAG_NOTIFY), \
    _AF_ATTR_ATTRDEF(65006, WIFI_STEADY_STATE,    AF_ATTR_TYPE_SINT8,  5, WIFISTAD,   AF_ATTR_FLAG_NOTIFY), \
    _AF_ATTR_ATTRDEF(65007, WIFI_SETUP_STATE,     AF_ATTR_TYPE_SINT8,  5, WIFISTAD,   AF_ATTR_FLAG_NOTIFY | AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65008, NETWORK_TYPE,         AF_ATTR_TYPE_SINT8,  5, CONNMGR,    AF_ATTR_FLAG_NOTIFY), \
    _AF_ATTR_ATTRDEF(65012, COMMAND,              AF_ATTR_TYPE_BYTES,  5, HUBBY,      AF_ATTR_FLAG_NOTIFY), \
    _AF_ATTR_ATTRDEF(65013, ASR_STATE,            AF_ATTR_TYPE_SINT8,  5, HUBBY,      AF_ATTR_FLAG_NOTIFY), \
    _AF_ATTR_ATTRDEF(65015, LINKED_TIMESTAMP,     AF_ATTR_TYPE_SINT32, 5, HUBBY,      AF_ATTR_FLAG_NOTIFY), \
    _AF_ATTR_ATTRDEF(65019, REBOOT_REASON,        AF_ATTR_TYPE_UTF8S,  5, ATTRD,      AF_ATTR_FLAG_NOTIFY), \
    _AF_ATTR_ATTRDEF(65022, NET_CAPABILITIES,     AF_ATTR_TYPE_SINT8,  5, CONNMGR,    AF_ATTR_FLAG_NOTIFY), \
    _AF_ATTR_ATTRDEF(65024, WIFI_ITF_STATE,       AF_ATTR_TYPE_SINT8,  5, CONNMGR,    AF_ATTR_FLAG_NOTIFY), \
    _AF_ATTR_ATTRDEF(65025, WIFI_IPADDR,          AF_ATTR_TYPE_BYTES,  5, CONNMGR,    AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65026, WIFI_UPTIME,          AF_ATTR_TYPE_SINT32, 5, CONNMGR,    AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65027, WIFI_DL_DATA_USAGE,   AF_ATTR_TYPE_SINT32, 5, CONNMGR,    AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65028, WIFI_UL_DATA_USAGE,   AF_ATTR_TYPE_SINT32, 5, CONNMGR,    AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65029, WIFI_MAC_ADDR,        AF_ATTR_TYPE_BYTES,  5, CONNMGR,    AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65030, WIFI_KEY_MGMT,        AF_ATTR_TYPE_SINT8,  5, WIFISTAD,   AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65031, WIFI_GROUP_CIPHER,    AF_ATTR_TYPE_SINT8,  5, WIFISTAD,   AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65032, WIFI_PAIRWISE_CIPHER, AF_ATTR_TYPE_SINT8,  5, WIFISTAD,   AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65034, WAN_RSRP,             AF_ATTR_TYPE_SINT8,  5, WAN,        AF_ATTR_FLAG_NOTIFY), \
    _AF_ATTR_ATTRDEF(65035, WAN_BARS,             AF_ATTR_TYPE_SINT8,  5, WAN,        AF_ATTR_FLAG_NOTIFY), \
    _AF_ATTR_ATTRDEF(65037, WAN_ITF_STATE,        AF_ATTR_TYPE_SINT8,  5, CONNMGR,    AF_ATTR_FLAG_NOTIFY), \
    _AF_ATTR_ATTRDEF(65038, WAN_IPADDR,           AF_ATTR_TYPE_BYTES,  5, CONNMGR,    AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65039, WAN_UPTIME,           AF_ATTR_TYPE_SINT32, 5, CONNMGR,    AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65040, WAN_DL_DATA_USAGE,    AF_ATTR_TYPE_SINT32, 5, CONNMGR,    AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65041, WAN_UL_DATA_USAGE,    AF_ATTR_TYPE_SINT32, 5, CONNMGR,    AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65042, WAN_IMEISV,           AF_ATTR_TYPE_UTF8S,  5, WAN,        AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65043, WAN_IMSI,             AF_ATTR_TYPE_UTF8S,  5, WAN,        AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65044, WAN_ICCID,            AF_ATTR_TYPE_UTF8S,  5, WAN,        AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65045, WAN_RAT,              AF_ATTR_TYPE_SINT8,  5, WAN,        AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65046, WAN_REG_STATE,        AF_ATTR_TYPE_SINT8,  5, WAN,        AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65047, WAN_PS_STATE,         AF_ATTR_TYPE_SINT8,  5, WAN,        AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65048, WAN_MCC,              AF_ATTR_TYPE_UTF8S,  5, WAN,        AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65049, WAN_MNC,              AF_ATTR_TYPE_UTF8S,  5, WAN,        AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65050, WAN_LAC,              AF_ATTR_TYPE_SINT32, 5, WAN,        AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65051, WAN_CELL_ID,          AF_ATTR_TYPE_SINT32, 5, WAN,        AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65052, WAN_ROAMING_STATE,    AF_ATTR_TYPE_SINT8,  5, WAN,        AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65053, WAN_PLMN,             AF_ATTR_TYPE_UTF8S,  5, WAN,        AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65054, WAN_APN,              AF_ATTR_TYPE_UTF8S,  5, WAN,        AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65055, WAN_SIM_STATUS,       AF_ATTR_TYPE_SINT8,  5, WAN,        AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65056, WAN_DL_BIT_RATE,      AF_ATTR_TYPE_SINT32, 5, WAN,        AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65057, WAN_UL_BIT_RATE,      AF_ATTR_TYPE_SINT32, 5, WAN,        AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65059, ETH_ITF_STATE,        AF_ATTR_TYPE_SINT8,  5, CONNMGR,    AF_ATTR_FLAG_NOTIFY), \
    _AF_ATTR_ATTRDEF(65060, ETH_IPADDR,           AF_ATTR_TYPE_BYTES,  5, CONNMGR,    AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65061, ETH_UPTIME,           AF_ATTR_TYPE_SINT32, 5, CONNMGR,    AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65062, ETH_DL_DATA_USAGE,    AF_ATTR_TYPE_SINT32, 5, CONNMGR,    AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65063, ETH_UL_DATA_USAGE,    AF_ATTR_TYPE_SINT32, 5, CONNMGR,    AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65064, ETH_MAC_ADDR,         AF_ATTR_TYPE_BYTES,  5, CONNMGR,    AF_ATTR_FLAG_MCU_HIDE), \
    _AF_ATTR_ATTRDEF(65065, SYSTEM_TIME,          AF_ATTR_TYPE_SINT32, 5, ATTRD,      AF_ATTR_FLAG_MCU_HIDE), \

#define _AF_ATTR_ATTRDEF(_attr_id_num,_attr_id_name,_attr_type,_attr_get_timeout,_attr_owner,_attr_flags) AF_ATTR_##_attr_owner##_##_attr_id_name=_attr_id_num

typedef enum {
     _AF_ATTR_ATTRIBUTES
} af_attribute_id_t;

#undef _AF_ATTR_ATTRDEF

#define _AF_ATTR_OWNERDEF(_owner) AF_ATTR_OWNER_##_owner

typedef enum {
    _AF_ATTR_OWNERS
} af_attribute_owner_t;

#undef _AF_ATTR_OWNERDEF

/* Set timeout */
#define AF_ATTR_SET_TIMEOUT (5)

#endif // __AF_ATTR_DEF_H__
