dnl config.m4 for signalforge_dotenv extension

PHP_ARG_ENABLE([signalforge_dotenv],
  [whether to enable signalforge_dotenv support],
  [AS_HELP_STRING([--enable-signalforge-dotenv],
    [Enable signalforge_dotenv support])],
  [no])

if test "$PHP_SIGNALFORGE_DOTENV" != "no"; then
  dnl Check for libsodium
  AC_MSG_CHECKING([for libsodium])

  dnl Try pkg-config first
  if test -z "$PKG_CONFIG"; then
    AC_PATH_PROG(PKG_CONFIG, pkg-config, no)
  fi

  if test -x "$PKG_CONFIG" && $PKG_CONFIG --exists libsodium; then
    SODIUM_CFLAGS=`$PKG_CONFIG --cflags libsodium`
    SODIUM_LIBS=`$PKG_CONFIG --libs libsodium`
    SODIUM_VERSION=`$PKG_CONFIG --modversion libsodium`
    AC_MSG_RESULT([found version $SODIUM_VERSION via pkg-config])
  else
    dnl Fallback: check for sodium.h directly
    AC_CHECK_HEADER([sodium.h], [
      SODIUM_CFLAGS=""
      SODIUM_LIBS="-lsodium"
      AC_MSG_RESULT([found via header check])
    ], [
      AC_MSG_ERROR([libsodium not found. Please install libsodium-dev])
    ])
  fi

  dnl Verify sodium library is linkable
  saved_CFLAGS="$CFLAGS"
  saved_LIBS="$LIBS"
  CFLAGS="$CFLAGS $SODIUM_CFLAGS"
  LIBS="$LIBS $SODIUM_LIBS"

  AC_CHECK_LIB([sodium], [sodium_init], [], [
    AC_MSG_ERROR([libsodium library not usable])
  ])

  CFLAGS="$saved_CFLAGS"
  LIBS="$saved_LIBS"

  dnl Add sodium flags
  PHP_EVAL_INCLINE($SODIUM_CFLAGS)
  PHP_EVAL_LIBLINE($SODIUM_LIBS, SIGNALFORGE_DOTENV_SHARED_LIBADD)

  dnl Define source files
  PHP_NEW_EXTENSION(signalforge_dotenv,
    signalforge_dotenv.c src/parser.c src/crypto.c src/env.c,
    $ext_shared,, -DZEND_ENABLE_STATIC_TSRMLS_CACHE=1 -Wall -Wextra -Werror=implicit-function-declaration)

  PHP_SUBST(SIGNALFORGE_DOTENV_SHARED_LIBADD)

  dnl Add src directory to include path
  PHP_ADD_BUILD_DIR($ext_builddir/src)
  PHP_ADD_INCLUDE($ext_srcdir/src)

  AC_DEFINE(HAVE_SIGNALFORGE_DOTENV, 1, [Whether signalforge_dotenv is enabled])
fi
