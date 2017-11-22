AUTOMAKE_OPTIONS = subdir-objects
bin_PROGRAMS = attrd attr_test attrc
lib_LIBRARIES = libaf_attr.a
include_HEADERS = af_attr_def.h af_attr_client.h

attrd_SOURCES = attrd.c attrd_attr.c attr_common.c
attrd_LDADD = -L. -levent_pthreads -lpthread -levent -laf_ipc -laf_util
attrd_CFLAGS = -Wall -std=gnu99 -ggdb3

attr_test_SOURCES = attr_test.c
attr_test_LDADD = -L. -laf_attr -levent_pthreads -lpthread -levent -laf_ipc -laf_util
attr_test_CFLAGS = -Wall -std=gnu99 -ggdb3

attrc_SOURCES = attrc.c
attrc_LDADD = -L. -laf_attr -levent_pthreads -lpthread -levent -laf_ipc -laf_util
attrc_CFLAGS = -Wall -std=gnu99 -ggdb3

libaf_attr_a_SOURCES = attr_api.c attr_common.c
libaf_attr_a_LDLIBS = -L. -levent -laf_ipc -laf_util

if BUILD_TYPE_DEV
libaf_attr_a_CFLAGS = -Wall -ggdb3 -std=gnu99
else
libaf_attr_a_CFLAGS = -Wall -ggdb3 -std=gnu99 -DNDEBUG
endif

.PHONY : build_info.h
$(attrd_SOURCES) : build_info.h
build_info.h :
	$(srcdir)/make-build-info.sh $(srcdir)
