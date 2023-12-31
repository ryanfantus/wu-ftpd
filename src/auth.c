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
 
  $Id: auth.c,v 1.9 2011/10/20 22:58:10 wmaton Exp $
 
****************************************************************************/
#include "config.h"
#if defined(BSD_AUTH)
#  include <stdio.h>
#  include <string.h>
#  include <setjmp.h>
#  include <sys/wait.h>
#  include <sys/param.h>
#  include <pwd.h>
#  include <signal.h>
#  include <stdlib.h>

#  include <syslog.h>

#  include <login_cap.h>

int ext_auth = 0;
login_cap_t *class = NULL;
static char *challenge = NULL;

char *start_auth(char *style, char *name, struct passwd *pwd)
{
    int s;

    ext_auth = 1;		/* authentication is always external */

    if (challenge)
	free(challenge);
    challenge = NULL;

    if (!(class = login_getclass(pwd ? pwd->pw_class : 0)))
	return (NULL);

    if (pwd && pwd->pw_passwd[0] == '\0')
	return (NULL);

    if ((style = login_getstyle(class, style, "auth-ftp")) == NULL)
	return (NULL);

    if (auth_check(name, class->lc_class, style, "challenge", &s) < 0)
	return (NULL);

    if ((s & AUTH_CHALLENGE) == 0)
	return (NULL);

    challenge = auth_value("challenge");
    return (challenge);
}

char *check_auth(char *name, char *passwd)
{
    char *e;
    int r;

    if (ext_auth == 0)
	return ("Login incorrect.");
    ext_auth = 0;

    r = auth_response(name, class->lc_class, class->lc_style, "response",
		      NULL, challenge ? challenge : "", passwd);

    if (challenge)
	free(challenge);
    challenge = NULL;

    if (r <= 0) {
	e = auth_value("errormsg");
	return (e ? e : "Login incorrect.");
    }

    if (!auth_approve(class, name, "ftp")) {
	syslog(LOG_INFO | LOG_AUTH,
	       "FTP LOGIN FAILED (HOST) as %s: approval failure.", name);
	return ("Approval failure.");
    }


    return (NULL);
}
#endif /* defined(BSD_AUTH) */ 
