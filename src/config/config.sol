/****************************************************************************    
  Copyright (c) 1999-2003 WU-FTPD Development Group.  
  All rights reserved.
   
  Portions Copyright (c) 1980, 1985, 1988, 1989, 1990, 1991, 1993, 1994  
    The Regents of the University of California. 
  Portions Copyright (c) 1993, 1994 Washington University in Saint Louis.  
  Portions Copyright (c) 1996, 1998 Berkeley Software Design, Inc.  
  Portions Copyright (c) 1989 Massachusetts Institute of Technology.  
  Portions Copyright (c) 1998 Sendmail, Inc.  
  Portions Copyright (c) 1983, 1995, 1996, 1997 Eric P.  Allman.  
  Portions Copyright (c) 1997 by Stan Barber.  
  Portions Copyright (c) 1997 by Kent Landfield.  
  Portions Copyright (c) 1991, 1992, 1993, 1994, 1995, 1996, 1997  
    Free Software Foundation, Inc.    
   
  Use and distribution of this software and its source code are governed   
  by the terms and conditions of the WU-FTPD Software License ("LICENSE").  
   
  If you did not receive a copy of the license, it may be obtained online  
  at http://www.wu-ftpd.info/license.html.  
   
  $Id: config.sol,v 1.9 2011/10/20 22:58:12 wmaton Exp $  
   
****************************************************************************/
/*
   ** config.h for Solaris 2.X 
 */

/* On Solaris 2.6 or later, to support files >2Gb uncomment the next line */
/* #define _FILE_OFFSET_BITS 64 */
#define HAVE_LSTAT
#undef F_SETOWN
#define HAVE_DIRENT_H
#define HAVE_D_NAMLEN
#undef HAVE_FLOCK
#define HAVE_FTW
#define HAVE_GETCWD
#undef HAVE_GETDTABLESIZE
#define HAVE_GETRLIMIT
#undef HAVE_PSTAT
#define HAVE_STATVFS
#define HAVE_ST_BLKSIZE
#define HAVE_SYSINFO
#define HAVE_SYSCONF
#undef HAVE_UT_UT_HOST
#define HAVE_VPRINTF
#define HAVE_FCNTL_H
#define HAVE_SIGPROCMASK
#define HAVE_REGEX
/* To enable PAM on Solaris, undef SHADOW_PASSWORD and #define USE_PAM */
#define SHADOW_PASSWORD 1
#define SOLARIS_2
#if _FILE_OFFSET_BITS == 64
#  define L_FORMAT "lld"
#else /* !(_FILE_OFFSET_BITS == 64) */ 
#  define L_FORMAT "ld"
#endif /* !(_FILE_OFFSET_BITS == 64) */ 
#define T_FORMAT "ld"
#define PW_UID_FORMAT "ld"
#define GR_GID_FORMAT "ld"
#define SVR4
#define HAVE_FCNTL_H
#define HAVE_FGETPWENT
#define HAVE_MKSTEMP
/* If wtmp is obsolete on your Solaris system, add #define NO_UTMP */
/* If your Solaris system has closefrom(3C), add #define CLOSEFROM */
#define USE_VAR
#define USE_ETC_FTPD
#if !defined(USE_ETC_FTPD) && !defined(USE_LOCAL_ETC) && !defined(USE_OPT_FTPD)
#  define USE_ETC
#endif /* !defined(USE_ETC_FTPD) && !defined(USE_LOCAL_ETC) && !defined(USE_OPT_FTPD) */ 

#include <limits.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#if !defined(FACILITY)
#  define FACILITY LOG_DAEMON
#endif /* !defined(FACILITY) */ 

#if !defined(HAVE_SIGNAL_TYPE)
#  define HAVE_SIGNAL_TYPE 1
typedef void SIGNAL_TYPE;
#endif /* !defined(HAVE_SIGNAL_TYPE) */ 

#include "../config.h"

#define QUOTA
#define VIRTUAL
#define HAVE_SIN6_SCOPE_ID
