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
 
  $Id: lastlog.c,v 1.8 2011/10/20 22:58:10 wmaton Exp $
 
****************************************************************************/
/***********************************************************
 *                                                         *
 * File: lastlog.c                                         *
 *                                                         *
 * Description: Records user login in the lastlog file.    *
 *                                                         *
 * Author: Sylvain Robitaille                              *
 *                                                         *
 * Date: 2000/10/19: adapted from patch to IMAPd           *
 *                                                         *
 ***********************************************************/

/***********************************************************
 *                                                         *
 * Include files                                           *
 *                                                         *
 ***********************************************************/
#include "config.h"

#if defined(USE_LASTLOG)

#  if defined(HAVE_LOGIN_H)
#    include <login.h>
#  endif /* defined(HAVE_LOGIN_H) */ 
#  if defined(HAVE_LASTLOG_H)
#    include <lastlog.h>
#  endif /* defined(HAVE_LASTLOG_H) */ 
#  if defined(HAVE_UTMP_H)
#    include <utmp.h>
#  endif /* defined(HAVE_UTMP_H) */ 

#if defined(TIME_WITH_SYS_TIME)
#  include <time.h>
#  include <sys/time.h>
#else /* !(defined(TIME_WITH_SYS_TIME)) */
#  if defined(HAVE_SYS_TIME_H)
#    include <sys/time.h>
#  else /* !(defined(HAVE_SYS_TIME_H)) */
#    include <time.h>
#  endif /* !(defined(HAVE_SYS_TIME_H)) */
#endif /* !(defined(TIME_WITH_SYS_TIME)) */

#  include <fcntl.h>
#  include <pwd.h>
#  include <unistd.h>
#  include <syslog.h>
#  include <errno.h>
#  include <string.h>
#  include "pathnames.h"
#  include "proto.h"

/***************************************************************
 *                                                             *
 * Function: update_lastlog                                    *
 *                                                             *
 * Description: records the user's activity in the system      *
 *              lastlog file.                                  *
 *                                                             *
 * Author: Sylvain Robitaille                                  *
 *                                                             *
 * Date: 1997/11/21: borrowed code from ssh source.            *
 *       2000/07/31: Call with the uid as a parameter          *
 *       2000/10/19: Add to Wu-Ftpd-2.6.0, hostname parameter  *
 *       2001/09/04: Add line parameter                        *
 *                                                             *
 ***************************************************************/
void update_lastlog(char *line, uid_t uid, char *host)
{
    int fd;
    mode_t oldmask;
    off_t offset;
    struct lastlog ll;
    const char *lastlog = _PATH_LASTLOG;

    /*
     * Update the lastlog file.
     */
    oldmask = umask(0);
    fd = open(lastlog, O_RDWR | O_CREAT, 0444);
    (void) umask(oldmask);
    if (fd >= 0) {
	offset = (off_t)uid * (off_t)sizeof(ll);
	if (lseek(fd, offset, SEEK_SET) != offset) {
	    syslog(LOG_INFO, "Could not lseek %s: %s", lastlog,
		   strerror(errno));
	    close(fd);
	    return;
	}

	/* Initialize the lastlog structure */
	memset(&ll, 0, sizeof(ll));

	/* Fill in the data */
	ll.ll_time = time(NULL);
	strncpy(ll.ll_line, line, sizeof(ll.ll_line));
	strncpy(ll.ll_host, host, sizeof(ll.ll_host));

	if (write(fd, &ll, sizeof(ll)) != sizeof(ll))
	    syslog(LOG_INFO, "Could not write %s: %s", lastlog,
		   strerror(errno));
	close(fd);
    }
}
#endif /* defined(USE_LASTLOG) */ 
