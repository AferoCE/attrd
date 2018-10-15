/*
 * af_profile.h -- definitions for reading device profile
 *
 * N.B. The device profile is different from the attribute daemon profile
 * although when an attribute is present in both, the information in both
 * should be consistent.
 *
 * This API is available to users of the afLib library.
 *
 * Copyright (c) 2017-2018 Afero, Inc. All rights reserved.
 *
 */

#include "af_attr_def.h"

typedef struct {
    uint16_t attr_id;
    uint16_t type;          // from af_attribute_type
    uint16_t flags;         // from af_attribute_flag
    uint16_t max_length;
    uint16_t default_length;
    uint16_t pad;
    uint8_t *default_data;  // NULL if no default data
} af_profile_attr_t;

/*
 * profile description: the list of attributes and their id, type, and flags.
 */

enum af_profile_attr_flag {
    ATTR_FLAG_READ = 0x0001,
    ATTR_FLAG_READ_NOTIFY = 0x0002, /* deprecated */
    ATTR_FLAG_WRITE = 0x0004,
    ATTR_FLAG_WRITE_NOTIFY = 0x0008, /* deprecated */
    ATTR_FLAG_HAS_DEFAULT = 0x0010,
    ATTR_FLAG_LATCH = 0x0020,
    ATTR_FLAG_MCU_HIDE = 0x0040,
    ATTR_FLAG_PASS_THROUGH = 0x0080,
    ATTR_FLAG_STORE_IN_FLASH = 0x0100,
};

/* Loads a profile with the profile at the specified path or the default path (if the specified
 * path is NULL). Returns the number of attributes in it or -1 if there's an error
 */
int af_profile_load(const char *path);

/* returns NULL if failure; errno contains reason
 *     EINVAL - index out of range
 *     ENOENT - profile not loaded yet
 */
af_profile_attr_t *af_profile_get_attribute_at_index(int index);

/* returns NULL if failure; errno contains reason
 *     EINVAL - id not found
 *     ENOENT - profile not loaded yet
 */
af_profile_attr_t *af_profile_get_attribute_with_id(uint16_t id);

/* for the orderly cleanup of an app */
void af_profile_free(void);

/* dump the profile to syslog */
void af_profile_dump(void);
