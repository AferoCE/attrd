/*
 * load the binary profile to determine the type of each attribute.
 */

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "af_profile.h"
#include "af_log.h"
#include "af_util.h"

#define DEFAULT_PROFILE_FILENAME "/etc/hub.profile"

#define MAX_PROFILE_SIZE (1L << 20)

#define IMAGE_HEADER_LENGTH 216
#define PROFILE_HEADER_LENGTH 6
#define ATTR_HEADER_LENGTH 8

typedef struct {
    uint16_t attribute_count;
    af_profile_attr_t *attributes;
} af_profile_t;

static af_profile_t *sProfile = NULL;

static int profile_parse(af_profile_t *profile, const uint8_t *buffer, size_t len) {
    size_t index = 0;
    if (len < IMAGE_HEADER_LENGTH + PROFILE_HEADER_LENGTH) {
        AFLOG_ERR("%s_len:actual=%d,min=%d", __func__, len, IMAGE_HEADER_LENGTH + PROFILE_HEADER_LENGTH);
        errno = EINVAL;
        return -1;
    }

    index += IMAGE_HEADER_LENGTH;
    uint16_t version = buffer[index] + (buffer[index + 1] << 8);
    if (version != 2) {
        AFLOG_ERR("%s_version:actual=%d,max=%d", __func__, version, 2);
        errno = EINVAL;
        return -1;
    }
    uint16_t attribute_count = buffer[index + 4] + (buffer[index + 5] << 8);
    index += PROFILE_HEADER_LENGTH;

    profile->attribute_count = attribute_count;
    profile->attributes = calloc(attribute_count, sizeof(af_profile_attr_t));

    for (int i = 0; i < attribute_count; i++) {
        // truncated?
        if (index + ATTR_HEADER_LENGTH > len) {
            profile->attribute_count = i;
            break;
        }

        af_profile_attr_t *attr = &profile->attributes[i];
        attr->attr_id = buffer[index] + (buffer[index + 1] << 8);
        attr->type = buffer[index + 2] + (buffer[index + 3] << 8);
        attr->flags = buffer[index + 4] + (buffer[index + 5] << 8);
        attr->max_length = buffer[index + 6] + (buffer[index + 7] << 8);
        index += ATTR_HEADER_LENGTH;

        if (attr->flags & ATTR_FLAG_HAS_DEFAULT) {
            attr->default_length = buffer[index] + (buffer[index + 1] << 8);
            if (attr->default_length) {
                attr->default_data = (uint8_t *)malloc(attr->default_length);

                if (attr->default_data) {
                    memcpy(attr->default_data, &buffer[index + 2], attr->default_length);
                }
            }
            index += 2 + attr->default_length;
        }
    }

    return 0;
}

static uint8_t *load_file(const char *filename, size_t *len) {
    *len = 0;
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        AFLOG_ERR("%s_open:errno=%d", __func__, errno);
        return NULL;
    }

    struct stat statbuf;
    if (fstat(fd, &statbuf) < 0) {
        AFLOG_ERR("%s_stat:errno=%d", __func__, errno);
        goto error;
    }
    if (statbuf.st_size > MAX_PROFILE_SIZE) {
        AFLOG_ERR("%s_too_big:size=%ld,MAX_PROFILE_SIZE=%ld", __func__, statbuf.st_size, MAX_PROFILE_SIZE);
        errno = EINVAL;
        goto error;
    }

    *len = statbuf.st_size;
    uint8_t *buffer = calloc(1, *len);
    if (buffer == NULL) goto error;
    int res = read(fd, buffer, *len);
    if (res < *len) {
        AFLOG_ERR("%s_read:res=%d,*len=%d,errno=%d", __func__, res, *len, errno);
        free(buffer);
        goto error;
    }
    return buffer;

error:
    close(fd);
    *len = 0;
    return NULL;
}

void af_profile_free(void) {
    if (sProfile) {
        for (int i = 0; i < sProfile->attribute_count; i++) {
            if (sProfile->attributes[i].default_data) {
                free(sProfile->attributes[i].default_data);
            }
        }
        free(sProfile->attributes);
        free(sProfile);
        sProfile = NULL;
    }
}

static uint8_t sProfileVersion[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
#define PROFILE_VERSION_OFFSET 202

static int is_new_version(const char *path)
{
    int fd = open(path ? path : DEFAULT_PROFILE_FILENAME, O_RDONLY);
    if (fd < 0) {
        AFLOG_ERR("%s_open:errno=%d", __func__, errno);
        goto err;
    }
    if (lseek(fd, PROFILE_VERSION_OFFSET, SEEK_SET) < 0) {
        AFLOG_ERR("%s_lseek:errno=%d", __func__, errno);
        goto err;
    }
    uint8_t currentVersion[8];
    if (read(fd, currentVersion, sizeof(currentVersion)) != sizeof(currentVersion)) {
        AFLOG_ERR("%s_read:errno=%d", __func__, errno);
        goto err;
    }
    int ret = memcmp(currentVersion, sProfileVersion, sizeof(currentVersion)) != 0;
    if (ret) {
        memcpy(sProfileVersion, currentVersion, sizeof(currentVersion));
    }
    return ret;

err:
    /* we're going to clear the profile version to guarantee that we can load it next time */
    memset(sProfileVersion, 0, sizeof(sProfileVersion));
    return -1;
}

/*
 * parse a binary profile from a file, and fill in a compact table of the
 * attributes, their ids, and types.
 */

int af_profile_load(const char *path)
{
    int isNew = is_new_version(path);
    if (isNew < 0) {
        AFLOG_INFO("%s_version_error::ignoring profile until the next time hubby starts", __func__);
        return -1;
    }

    uint64_t version = 0;
    for (int i = 0; i < sizeof(sProfileVersion); i++) {
        version <<= 8;
        version |= (uint64_t)sProfileVersion[sizeof(sProfileVersion) - i - 1];
    }

    if (!isNew) {
        AFLOG_INFO("%s_version_same:version=%llu:already have latest profile", __func__, version);
        return 0;
    } else {
        AFLOG_INFO("%s_version_different:newVersion=%llu:loading new profile", __func__, version);
    }

    af_profile_free();

    sProfile = calloc(1, sizeof(af_profile_t));
    if (!sProfile) {
        return -1;
    }

    size_t len;
    uint8_t *data = load_file(path ? path : DEFAULT_PROFILE_FILENAME, &len);
    if (!data) {
        free(sProfile);
        return -1;
    }

    int res = profile_parse(sProfile, data, len);
    free(data);
    if (res) {
        af_profile_free();
        return res;
    }
    return sProfile->attribute_count;
}

af_profile_attr_t *af_profile_get_attribute_at_index(int index) {
    if (sProfile == NULL) {
        /* no profile loaded */
        errno = ENOENT;
        return NULL;
    }
    if (index < 0 || index >= sProfile->attribute_count) {
        errno = EINVAL;
        return NULL;
    }

    return &sProfile->attributes[index];
}

af_profile_attr_t *af_profile_get_attribute_with_id(uint16_t id) {
    if (sProfile == NULL) {
        /* no profile loaded */
        errno = ENOENT;
        return NULL;
    }
    for (int i = 0; i < sProfile->attribute_count; i++) {
        if (sProfile->attributes[i].attr_id == id) {
            return &sProfile->attributes[i];
        }
    }

    errno = EINVAL;
    return NULL;
}

void af_profile_dump(void) {
    if (sProfile == NULL) {
        AFLOG_INFO("sProfile=NULL");
        return;
    }
    for (int i = 0; i < sProfile->attribute_count; i++) {
        af_profile_attr_t *a = &sProfile->attributes[i];
        AFLOG_INFO("  attr_id=%d,type=%d,flags=%x,max_len=%d,def_len=%d", a->attr_id, a->type, a->flags, a->max_length, a->default_length);
    }
}
