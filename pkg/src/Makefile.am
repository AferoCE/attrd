AUTOMAKE_OPTIONS = subdir-objects
if BUILD_TARGET_DEBUG
bin_PROGRAMS = attrd attr_test attrc
else
bin_PROGRAMS = attrd attrc
endif
lib_LIBRARIES = libaf_attr.a
include_HEADERS = af_attr_def.h af_attr_client.h af_profile.h

if BUILD_TARGET_DEBUG
CFLAGS_BUILD_TARGET = -DBUILD_TARGET_DEBUG
else
CFLAGS_BUILD_TARGET = -DBUILD_TARGET_RELEASE
endif

attrd_SOURCES = attrd.c attrd_attr.c attr_common.c value_formats.c attr_script.c profile.c
attrd_LDFLAGS = -ggdb3 -L. -levent_pthreads -lpthread -levent -laf_ipc -laf_util
attrd_CFLAGS = -Wall -Werror -std=gnu99 $(CFLAGS_BUILD_TARGET)

if BUILD_TARGET_DEBUG
attr_test_SOURCES = attr_test.c
attr_test_LDADD = -L. -laf_attr -levent_pthreads -lpthread -levent -laf_ipc -laf_util
attr_test_CFLAGS = -Wall -Werror -std=gnu99 $(CFLAGS_BUILD_TARGET)
endif

attrc_SOURCES = attrc.c value_formats.c profile.c
attrc_LDFLAGS = -ggdb3 -L. -laf_attr -levent_pthreads -lpthread -levent -laf_ipc -laf_util
attrc_CFLAGS = -Wall -Werror -std=gnu99 $(CFLAGS_BUILD_TARGET)

libaf_attr_a_SOURCES = attr_api.c attr_common.c profile.c
libaf_attr_a_CFLAGS = -Wall -std=gnu99 $(CFLAGS_BUILD_TARGET)
libaf_attr_a_LDLIBS = -L. -levent -laf_ipc -laf_util

.PHONY : build_info.h
$(attrd_SOURCES) : build_info.h
build_info.h :
	$(srcdir)/make-build-info.sh $(srcdir)
