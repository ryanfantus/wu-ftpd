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
  
  $Id: logwtmp.c,v 1.9 2011/10/20 22:58:10 wmaton Exp $ 
  
****************************************************************************/
#include "config.h"

#include <sys/types.h>
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
#include <sys/stat.h>
#if defined(HAVE_FCNTL_H)
#  include <fcntl.h>
#endif /* defined(HAVE_FCNTL_H) */ 
#include <utmp.h>
#if defined(SVR4)
#  if !defined(NO_UTMPX)
#    include <utmpx.h>
#    if !defined(_SCO_DS)
#      include <sac.h>
#    endif /* !defined(_SCO_DS) */ 
#  endif /* !defined(NO_UTMPX) */ 
#endif /* defined(SVR4) */ 
#if defined(BSD)
#  include <strings.h>
#else /* !(defined(BSD)) */ 
#  include <string.h>
#endif /* !(defined(BSD)) */ 
#if defined(HAVE_SYS_SYSLOG_H)
#  include <sys/syslog.h>
#endif /* defined(HAVE_SYS_SYSLOG_H) */ 
#if defined(HAVE_SYSLOG_H) || (!defined(AUTOCONF) && !defined(HAVE_SYS_SYSLOG_H))
#  include <syslog.h>
#endif /* defined(HAVE_SYSLOG_H) || (!defined(AUTOCONF) && !defined(HAVE_SYS_SYSLOG_H)) */ 
#if defined(__FreeBSD__)
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <netdb.h>
#endif /* defined(__FreeBSD__) */ 

#include "pathnames.h"
#include "proto.h"

#if !defined(NO_UTMP)
static int fd = -1;
#endif /* !defined(NO_UTMP) */ 
#if defined(SVR4) && !defined(NO_UTMPX)
static int fdx = -1;
#endif /* defined(SVR4) && !defined(NO_UTMPX) */ 

/* Modified version of logwtmp that holds wtmp file open after first call,
 * for use with ftp (which may chroot after login, but before logout). */

void wu_logwtmp(char *line, char *name, char *host, int login)
{
    struct stat buf;
#if !defined(NO_UTMP)
    struct utmp ut;
#endif /* !defined(NO_UTMP) */ 

#if defined(SVR4) && !defined(NO_UTMPX)
    /*
     * Date: Tue, 09 Mar 1999 14:59:42 -0600
     * From: Chad Price <cprice@molbio.unmc.edu>
     * To: wu-ftpd@wugate.wustl.edu
     * Subject: Re: Problem w/ Solaris /var/adm/wtmpx and /usr/bin/last(1)
     * 
     * I've been running Sol 2.4 since it came out, and the 'last' command
     * has never worked correctly, for ftpd or logins either one.  wtmpx
     * often fails to close out sessions when the user logs out.  As a
     * result, I only use last to see who logged in, not who/when the
     * logout occurred.
     * 
     * When I first installed it, it was even worse, and they immediately
     * told me to patch the system.  This fixed it to semi-compus mentis,
     * but not to working order.  So I guess my conclusion is: ignore the
     * wtmpx / last log stuff on Solaris 2.4 (and other releases of Solaris
     * too from what I see in the comments), it's broken and always has
     * been.  I do of course stand ready to be corrected (in this case,
     * pointed to a patch which really does fix it.)
     *
     */
    struct utmpx utx;

    if (fdx < 0 && (fdx = open(WTMPX_FILE, O_WRONLY | O_APPEND, 0)) < 0) {
	syslog(LOG_ERR, "wtmpx %s %m", WTMPX_FILE);
	return;
    }

    if (fstat(fdx, &buf) == 0) {
	memset((void *) &utx, '\0', sizeof(utx));
	(void) strncpy(utx.ut_user, name, sizeof(utx.ut_user));
	(void) strncpy(utx.ut_host, host, sizeof(utx.ut_host));
	(void) strncpy(utx.ut_id, "ftp", sizeof(utx.ut_id));
	(void) strncpy(utx.ut_line, line, sizeof(utx.ut_line));
	utx.ut_syslen = strlen(utx.ut_host) + 1;
	utx.ut_pid = getpid();
	(void) time(&utx.ut_tv.tv_sec);
	if (login /* name && *name */ ) {
	    utx.ut_type = USER_PROCESS;
	}
	else {
	    utx.ut_type = DEAD_PROCESS;
	}
	utx.ut_exit.e_termination = 0;
	utx.ut_exit.e_exit = 0;
	if (write(fdx, (char *) &utx, sizeof(struct utmpx)) !=
	    sizeof(struct utmpx))
	          (void) ftruncate(fdx, buf.st_size);
    }
#endif /* defined(SVR4) && !defined(NO_UTMPX) */ 

#if !defined(NO_UTMP)
#  if defined(__FreeBSD__)
    if (strlen(host) > UT_HOSTSIZE) {
	if ((host = inet_htop(host)) == NULL)
	    host = "invalid hostname";
    }
#  endif /* defined(__FreeBSD__) */ 

    if (fd < 0 && (fd = open(_PATH_WTMP, O_WRONLY | O_APPEND, 0)) < 0) {
	syslog(LOG_ERR, "wtmp %s %m", _PATH_WTMP);
	return;
    }
    if (fstat(fd, &buf) == 0) {
#  if defined(UTMAXTYPE)
	memset((void *) &ut, 0, sizeof(ut));
#    if defined(LINUX)
	(void) strncpy(ut.ut_id, "", sizeof(ut.ut_id));
#    else /* !(defined(LINUX)) */ 
	(void) strncpy(ut.ut_id, "ftp", sizeof(ut.ut_id));
#    endif /* !(defined(LINUX)) */ 
	(void) strncpy(ut.ut_line, line, sizeof(ut.ut_line));
	ut.ut_pid = getpid();
	if (login /* name && *name */ ) {
	    (void) strncpy(ut.ut_user, name, sizeof(ut.ut_user));
	    ut.ut_type = USER_PROCESS;
	}
	else
	    ut.ut_type = DEAD_PROCESS;
#    if defined(HAVE_UT_UT_EXIT_E_TERMINATION) || (!defined(AUTOCONF) && !defined(LINUX))
	ut.ut_exit.e_termination = 0;
	ut.ut_exit.e_exit = 0;
#    endif /* defined(HAVE_UT_UT_EXIT_E_TERMINATION) || (!defined(AUTOCONF) && !defined(LINUX)) */ 
#  else /* !(defined(UTMAXTYPE)) */ 
	(void) strncpy(ut.ut_line, line, sizeof(ut.ut_line));
	if (login) {
	    (void) strncpy(ut.ut_name, name, sizeof(ut.ut_name));
	}
	else {
	    (void) strncpy(ut.ut_name, "", sizeof(ut.ut_name));
	}
#  endif /* !(defined(UTMAXTYPE)) */ 
#  if defined(HAVE_UT_UT_HOST)		/* does have host in utmp */
	if (login) {
	    (void) strncpy(ut.ut_host, host, sizeof(ut.ut_host));
	}
	else {
	    (void) strncpy(ut.ut_host, "", sizeof(ut.ut_host));
	}
#  endif /* defined(HAVE_UT_UT_HOST)i - does have host in utmp */ 
	(void) time(&ut.ut_time);
	if (write(fd, (char *) &ut, sizeof(struct utmp)) !=
	    sizeof(struct utmp))
	         (void) ftruncate(fd, buf.st_size);
    }
#endif /* !defined(NO_UTMP) */ 
}
