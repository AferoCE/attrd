AC_INIT([attrd], [1.0], [bug-automake@gnu.org])

AM_INIT_AUTOMAKE([-Wall -Werror foreign])
: ${CFLAGS="-O0"}
AC_PROG_CC
AM_PROG_AR

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
 Makefile
 src/Makefile
])

AM_CONDITIONAL([BUILD_TYPE_DEV], [test x$BUILD_TYPE = xdev])

LT_INIT
AC_OUTPUT
