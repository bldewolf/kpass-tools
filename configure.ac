AC_PREREQ([2.65])
AC_INIT([kpass-tools], [3], [kpass-tools@bldewolf.com], [kpass-tools], [https://github.com/bldewolf/kpass-tools])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])

AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([-Wall -Werror])

# Checks for programs.
AC_PROG_CC()
gl_EARLY()
AM_PROG_CC_C_O()
AC_PROG_INSTALL()

gl_INIT()

# Checks for libraries.
AC_CHECK_LIB([kpass], [kpass_init_db], [], [AC_MSG_ERROR([Libkpass required.]); exit 1])
AC_CHECK_LIB([uuid], [uuid_compare], [], [AC_MSG_ERROR([Libuuid required.]); exit 1])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h termios.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([memset munmap])

AC_CONFIG_FILES([Makefile lib/Makefile])
AC_OUTPUT
