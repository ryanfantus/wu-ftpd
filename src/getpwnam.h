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
 
  $Id: getpwnam.h,v 1.9 2011/10/20 22:58:10 wmaton Exp $
 
****************************************************************************/
/*
 * Replacement for getpwnam - we need it to handle files other than
 * /etc/passwd so we can permit different passwd files for each different
 * host
 * 19980930	Initial version
 * 20000211	Various fixes
 */

#include <pwd.h>
#include <sys/types.h>
#include <stdio.h>
#if defined(SHADOW_PASSWORD)
#  if defined(HAVE_SHADOW_H)
#    include <shadow.h>
#  endif /* defined(HAVE_SHADOW_H) */ 
#endif /* defined(SHADOW_PASSWORD) */ 

struct passwd *bero_getpwnam(const char * name, const char * file);
struct passwd *bero_getpwuid(uid_t uid, const char * file);
#if defined(SHADOW_PASSWORD)
struct spwd *bero_getspnam(const char * name, const char * file);
#endif /* defined(SHADOW_PASSWORD) */ 
