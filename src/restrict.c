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
   
  $Id: restrict.c,v 1.9 2011/10/20 22:58:11 wmaton Exp $  
   
****************************************************************************/
/*
 * Contributed by Glenn Nielsen <glenn@more.net>
 * Mon, 18 Jan 1999 20:04:07 -0600
 */
#include "config.h"

#include <sys/param.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include "proto.h"

#if defined(HAVE_GETCWD)
extern char *getcwd(char *, size_t);
#else /* !(defined(HAVE_GETCWD)) */ 
extern char *getwd(char *);
#endif /* !(defined(HAVE_GETCWD)) */ 

#if !defined(TRUE)
#  define TRUE 1
#  define FALSE 0
#endif /* !defined(TRUE) */ 

extern char *home;
extern int restricted_user;

/*
 * name is the function parameter
 * home is a global string containing the user's home directory
 *
 * rhome is the resolved home directory
 * rname is the resolved requested filename
 * curwd is the current working directory
 * path is name, possibly prepended by the current working directory
 */

int restrict_check(char *name)
{
    if (!test_restriction(name))
	return 0;
    reply(550, "Permission denied on server.  You are restricted to your account.");
    return 1;
}

int test_restriction(char *name)
{
    char rhome[MAXPATHLEN + 1], rname[MAXPATHLEN + 1], path[MAXPATHLEN + 1];

    /* we're not in restrict mode so all access is OK */
    if (restricted_user == FALSE)
	return 0;

    /* get resolved equivalent of user's home directory */
    fb_realpath(home, rhome);

    path[0] = '\0';

    /* a relative path is specified, so resolve it w.r.t. current working directory */
    if ((name)[0] != '/') {
	char *pcwd;
	char curwd[MAXPATHLEN + 1];

	/* determine current working directory */
#if defined(HAVE_GETCWD)
	pcwd = getcwd(curwd, MAXPATHLEN);
#else /* !(defined(HAVE_GETCWD)) */ 
	pcwd = getwd(curwd);
#endif /* !(defined(HAVE_GETCWD)) */ 
	if (pcwd == NULL) {
	    if (errno != EACCES)
		return 1;
	    else {
		uid_t userid = geteuid();
		delay_signaling();
		seteuid(0);
#if defined(HAVE_GETCWD)
		pcwd = getcwd(curwd, MAXPATHLEN);
#else /* !(defined(HAVE_GETCWD)) */ 
		pcwd = getwd(curwd);
#endif /* !(defined(HAVE_GETCWD)) */ 
		seteuid(userid);
		enable_signaling();
		if (pcwd == NULL)
		    return 1;
	    }
	}

	strlcpy(path, curwd, sizeof(path));
	strlcat(path, "/", sizeof(path));

    }				/* if */

    if ((strlen(path) + strlen(name) + 2) > sizeof(path)) {
	return 1;
    }

    strlcat(path, name, sizeof(path));
    fb_realpath(path, rname);
    strlcat(rname, "/", sizeof(rname));

    if (strncmp(rhome, rname, strlen(rhome))) {
	return 1;
    }				/* if */

    return 0;
}				/* restrict_check */

int restrict_list_check(char *name)
{
    char *beg, *copy, *end;
    int flag;

    beg = name;

    while (*beg != '\0') {

	flag = 0;
	end = beg;
	while (*end && !isspace(*end))
	    ++end;
	if (!*end)
	    flag = 1;
	if (!flag)
	    *end = '\0';
	copy = strdup(beg);
	if (!flag)
	    *end = ' ';

	if (!copy) {
	    reply(550, "Permission denied on server.  Out of memory.");
	    return 1;

	}			/* if */

	if (restrict_check(copy)) {
	    free(copy);
	    return 1;
	}
	free(copy);
	beg = end;
	if (!flag)
	    ++beg;

    }				/* while */

    return 0;

}				/* restrict_list_check */

/*
 * $Log: restrict.c,v $
 * Revision 1.9  2011/10/20 22:58:11  wmaton
 * Update pointers from wu-ftpd.org to wu-ftpd.info.
 *
 * Revision 1.8  2009/04/19 10:35:38  wmaton
 * Update to 20080214.
 *
 * Revision 1.19  2003/05/19 18:44:50  wuftpd
 * - Copyright headers updated - " Copyright (c) 1999-2003 WU-FTPD Development Group."
 * - Changed some of the remaining strncpys to strlcpys
 *
 * Revision 1.18  2003/05/09 16:16:04  wuftpd
 * Changed strcpy and strncpy calls to strlcpy where appropriate.
 * Changed sprintf calls to snprintf where appropriate.
 * Changed strcat calls to strlcat where appropriate.
 * Added strlcat.c and strlcpy.c and supporting man page to libsupport.a.
 * Modified configure to test for strlcpy and strlcat availability and include it in libsupport.a if needed.
 *
 * Revision 1.17  2001/12/22 09:25:53  wuftpd
 * More indent C preprocessor directives updates.
 *
 * Revision 1.16  2001/03/16 23:13:33  wuftpd
 * Debuging restricted tests, alt-home
 *
 * Revision 1.15  2001/03/13 11:52:16  wuftpd
 * Update copyright
 *
 * Revision 1.14  2000/07/01 18:17:39  wuftpd
 *
 * Updated copyright statement for the WU-FTPD Development Group.
 *
 * Revision 1.13  1999/10/08 03:42:12  wuftpd
 * Fixed a bug in restrict_check which could allow access outside the users home
 *
 * Revision 1.12  1999/09/05 02:31:50  wuftpd
 * Add virtual and defaultserver support for email notification
 *
 * Revision 1.11  1999/09/02 19:35:48  wuftpd
 * CDUP was leaking information about restrictions.
 *
 * Revision 1.10  1999/09/02 14:04:29  wuftpd
 * Cleaning up.  Indented and removed some STDC checks
 *
 * Revision 1.9  1999/08/24 23:41:39  wuftpd
 * wu-ftpd-2.4.x RCS Ids removed and new Ids added for wu-ftpd.org usage.
 * WU-FTPD Development Group copyright headers added.
 * Original Copyright headers moved into the COPYRIGHT file.
 * COPYPRIGHT.c added to build for ftpshut and ftpd.
 *
 * Revision 1.2  1996/02/20 04:54:04  root
 * added #define to make gcc use HAVE_GETCWD
 *
 * Revision 1.1  1996/02/20 03:52:48  root
 * Initial revision
 *
 */
