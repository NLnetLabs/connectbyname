AC_PREREQ([2.68])
AC_INIT([connectbyname], [0.1.0], [willem@nlnetlabs.nl])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/connectbyname.c])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC

AC_CHECK_LIB([getdns], [getdns_context_set_listen_addresses],,
	[AC_MSG_ERROR([Missing dependency: getdns >= 1.1.0 ])],)
AC_CHECK_HEADER([getdns/getdns_extra.h],,
	[AC_MSG_ERROR([Missing dependency: getdns >= 1.1.0 ])],)

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
