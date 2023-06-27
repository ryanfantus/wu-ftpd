/****************************************************************************  
 
  Copyright (c) 2003 WU-FTPD Development Group.  
  All rights reserved.
  
  Use and distribution of this software and its source code are governed 
  by the terms and conditions of the WU-FTPD Software License ("LICENSE").
 
  If you did not receive a copy of the license, it may be obtained online
  at http://www.wu-ftpd.info/license.html.
 
  $Id: xferlog.c,v 1.5 2011/10/20 22:58:11 wmaton Exp $
 
****************************************************************************/

#include "config.h"
#include <string.h>
#include "extensions.h"
#include "proto.h"

#define DEFXFERFORMAT	"%T %Xt %R %Xn %XP %Xy %Xf %Xd %Xm %U ftp %Xa %u %Xc"

int xferdone = 0;
struct xferstat xfervalues;
char xferlog_format[MAXXFERSTRLEN] = DEFXFERFORMAT;

/*************************************************************************/
/* FUNCTION  : get_xferlog_format                                        */
/* PURPOSE   : Read the xferlog format string from ftpaccess into        */
/*             xferlog_format if it exists otherwise load default string */
/* ARGUMENTS : none                                                      */
/*************************************************************************/

void get_xferlog_format(void)
{
    int which;
    struct aclmember *entry = (struct aclmember *)NULL;

    /* xferlog format <formatstring> */
    xferlog_format[0] = '\0';
    while (getaclentry("xferlog", &entry)) {
	if (ARG0 && (strcasecmp(ARG0, "format") == 0)) {
	    for (which = 1; (which < MAXARGS) && ARG[which]; which++) {
		if (which > 1) {
		    if (strlcat(xferlog_format, " ",
			sizeof(xferlog_format)) >= sizeof(xferlog_format))
			break;
		}
		if (strlcat(xferlog_format, ARG[which],
		    sizeof(xferlog_format)) >= sizeof(xferlog_format))
		    break;
	    }
	    break;
	}
    }

    /* default xferlog format */
    if (xferlog_format[0] == '\0')
	(void) strlcpy(xferlog_format, DEFXFERFORMAT, sizeof(xferlog_format));
}
