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
   
  $Id: timeout.c,v 1.11 2011/10/20 22:58:11 wmaton Exp $  
   
****************************************************************************/
#include "config.h"
#include "proto.h"

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "extensions.h"

unsigned int timeout_idle = 900;	/* Command idle: 15 minutes */
unsigned int timeout_maxidle = 7200;	/* Command idle (MAX): 2 hours */
unsigned int timeout_data = 1200;	/* Data idle: 20 minutes */
unsigned int timeout_rfc931 = 10;	/* RFC931 session, total: 10 seconds */
unsigned int timeout_accept = 120;	/* Accepting data connection: 2 minutes */
unsigned int timeout_connect = 120;	/* Establishing data connection: 2 minutes */

/*SG
  Procedure load_timeout() is called twice:
  1.  (originaly)  In access_init() for class less timeouts
  2.  (new)  In ftpc.c for class based timeouts (overrides)

Basically the lines: 

timeout_xxxx = value;

are replaced with: 

if (ARG2 == NULL) {
    if (!is_xxx) timeout_xxxx = value;
}   
else if (strcasecmp(ARG2, class) == 0)
    timeout_xxxx = value;
        }

the code construct below was causing SIGfaults:

if ((ARG2 == NULL) && (!is_xxx))
    timeout_xxxxx = value;

so was changed to:

if (ARG2 == NULL) {
    if (!is_xxx) timeout_xxxxx = value;
}
    
S. Goulart   5 fev 2003
*/

void load_timeouts(void)
{
    struct aclmember *entry = NULL;
    unsigned long value;
    /*SG Start other class based additions */
    /*  is_idl means 'is idle class set?'  */

    char class[1024];
    int  is_idl = 0,
	is_rfc = 0,
	is_max = 0,
	is_dat = 0,
	is_acc = 0,
	is_con = 0;
 
    /*SG New call */
    (void) acl_getclass(class, sizeof(class));
    
    while (getaclentry("timeout", &entry)) {
	if ((ARG0 != NULL) && (ARG1 != NULL)) {
	    value = strtoul(ARG1, NULL, 0);
	    if (strcasecmp(ARG0, "rfc931") == 0) {
		if (ARG2 == NULL) {
		    if (!is_rfc) timeout_rfc931 = value;
		}
		else if (strcasecmp(ARG2, class) == 0) {
		    timeout_rfc931 = value;
		    is_rfc = 1;
		}
	    }
	    else if (value > 0) {
		if (strcasecmp(ARG0, "idle") == 0) {
		    if (ARG2 == NULL) {  
			if (!is_idl) timeout_idle = value;
		    }
		    else if (strcasecmp(ARG2, class) == 0) {
			timeout_idle = value;
			is_idl = 1;
		    }
		    if (timeout_maxidle < timeout_idle)
			timeout_maxidle = timeout_idle;
		}
		else if (strcasecmp(ARG0, "maxidle") == 0) {
		    if (ARG2 == NULL) {
			if (!is_max) timeout_maxidle = value;
		    }
		    else if (strcasecmp(ARG2, class) == 0) {
			timeout_maxidle = value;
			is_max = 1;
		    }
		    if (timeout_idle > timeout_maxidle)
			timeout_idle = timeout_maxidle;
		}
		else if (strcasecmp(ARG0, "data") == 0) {
		    if (ARG2 == NULL) {  
			if (!is_dat) timeout_data = value;
		    }
		    else if (strcasecmp(ARG2, class) == 0) {
			timeout_data = value;
			is_dat = 1;
		    }
		}
		else if (strcasecmp(ARG0, "accept") == 0) {
		    if (ARG2 == NULL) {
			if (!is_acc) timeout_accept = value;
		    }
		    else if (strcasecmp(ARG2, class) == 0) {
			timeout_accept = value;
			is_acc = 1;
		    }
		}
		else if (strcasecmp(ARG0, "connect") == 0) {
		    if (ARG2 == NULL) {
			if (!is_con) timeout_connect = value;
		    }
		    else if (strcasecmp(ARG2, class) == 0) {
			timeout_connect = value;
			is_con = 1;
		    }
		}
	    }
	}
    }
}
